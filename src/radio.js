import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import NeteaseCloudMusicApi from "NeteaseCloudMusicApi";
const { cloudsearch, song_url_v1 } = NeteaseCloudMusicApi;
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

const RADIO_DIR = "/tmp/radio";
const MAX_QUEUE = 50;
const REAL_IP = "116.25.146.177"; // Spoof Chinese IP for Netease geo-restriction bypass

class Radio extends EventEmitter {
  constructor() {
    super();
    this.queue = []; // [{ id, title, artist, duration, query, filePath, thumbnail }]
    this.currentTrack = null;
    this.volume = 80; // 0-100
    this.clients = new Set(); // connected HTTP stream clients
    this.ffmpegProc = null;
    this.isPlaying = false;
    this.webhookUrl = null;
    this.downloadingSet = new Set(); // track queries being downloaded

    fs.mkdirSync(RADIO_DIR, { recursive: true });
    console.log("[radio] initialized (source: Netease Cloud Music)");
  }

  // Search Netease Cloud Music for a track
  async _searchNetease(query) {
    console.log(`[radio] searching netease: "${query}"`);
    const result = await cloudsearch({
      keywords: query,
      type: 1, // songs
      limit: 5,
      realIP: REAL_IP,
    });

    const songs = result.body.result && result.body.result.songs;
    if (!songs || songs.length === 0) {
      console.log(`[radio] no results for: "${query}"`);
      return null;
    }

    // Check all songs for available audio URLs in parallel
    const urlChecks = songs.map((song) =>
      song_url_v1({ id: song.id, level: "exhigh", realIP: REAL_IP })
        .then((r) => ({ song, data: r.body.data?.[0] }))
        .catch(() => ({ song, data: null }))
    );
    const results = await Promise.all(urlChecks);

    // Collect all candidates with valid audio URLs (preserves search ranking)
    const candidates = [];
    for (const { song, data } of results) {
      if (data && data.url && data.code === 200) {
        candidates.push({
          neteaseId: song.id,
          title: song.name,
          artist: song.ar ? song.ar.map((a) => a.name).join(", ") : "Unknown",
          duration: Math.round((song.dt || 0) / 1000), // ms -> seconds
          thumbnail: song.al && song.al.picUrl ? song.al.picUrl : null,
          audioUrl: data.url,
          audioSize: data.size || 0,
        });
      }
    }

    if (candidates.length === 0) {
      console.log(`[radio] all results for "${query}" have no available audio URL`);
      return null;
    }

    console.log(`[radio] found ${candidates.length} candidate(s) for "${query}"`);
    return candidates;
  }

  // Download audio file from URL
  async _downloadFile(url, outputPath) {
    console.log(`[radio] downloading: ${url.slice(0, 80)}...`);
    const resp = await fetch(url, { signal: AbortSignal.timeout(60000) });
    if (!resp.ok) {
      throw new Error(`Download failed: HTTP ${resp.status}`);
    }
    const fileStream = fs.createWriteStream(outputPath);
    await pipeline(Readable.fromWeb(resp.body), fileStream);
    const stat = fs.statSync(outputPath);
    console.log(`[radio] downloaded: ${Math.round(stat.size / 1024)}KB -> ${outputPath}`);
  }

  // Get actual audio duration using ffprobe (returns seconds)
  _getFileDuration(filePath) {
    return new Promise((resolve) => {
      const proc = spawn("ffprobe", [
        "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        filePath,
      ]);
      let out = "";
      proc.stdout.on("data", (d) => { out += d.toString(); });
      proc.on("close", () => {
        const dur = parseFloat(out.trim());
        resolve(isNaN(dur) ? 0 : dur);
      });
      proc.on("error", () => resolve(0));
    });
  }

  // Search and download a track (skips tracks shorter than 60s)
  async downloadTrack(query) {
    if (this.downloadingSet.has(query)) {
      return null; // already downloading
    }
    this.downloadingSet.add(query);

    try {
      const candidates = await this._searchNetease(query);
      if (!candidates) {
        throw new Error(`No results for: ${query}`);
      }

      // Try each candidate — skip if too short
      for (const info of candidates) {
        const id = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
        const outputPath = path.join(RADIO_DIR, `${id}.mp3`);

        try {
          await this._downloadFile(info.audioUrl, outputPath);

          // Verify actual duration with ffprobe
          const realDuration = await this._getFileDuration(outputPath);
          if (realDuration > 0 && realDuration < 60) {
            console.log(`[radio] skipping "${info.title}" — too short (${Math.round(realDuration)}s < 60s)`);
            try { fs.unlinkSync(outputPath); } catch {}
            continue; // try next candidate
          }

          const track = {
            id,
            title: info.title || query,
            artist: info.artist || "Unknown",
            duration: realDuration > 0 ? Math.round(realDuration) : (info.duration || 0),
            query,
            filePath: outputPath,
            thumbnail: info.thumbnail || null,
          };

          console.log(`[radio] ready: "${track.title}" by ${track.artist} (${track.duration}s)`);
          return track;
        } catch (dlErr) {
          console.error(`[radio] download failed for "${info.title}":`, dlErr.message);
          try { fs.unlinkSync(outputPath); } catch {}
          continue; // try next candidate
        }
      }

      console.log(`[radio] all candidates for "${query}" failed or too short`);
      return null;
    } catch (err) {
      console.error(`[radio] download error for "${query}":`, err.message);
      return null;
    } finally {
      this.downloadingSet.delete(query);
    }
  }

  // Add a song to the queue by search query
  async addToQueue(query) {
    if (this.queue.length >= MAX_QUEUE) {
      return { ok: false, error: "Queue is full" };
    }

    const track = await this.downloadTrack(query);
    if (!track) {
      return { ok: false, error: `Failed to find/download: ${query}` };
    }

    this.queue.push(track);
    console.log(`[radio] queued: "${track.title}" (${this.queue.length} in queue)`);

    // If not playing, start
    if (!this.isPlaying) {
      this._playNext();
    }

    return {
      ok: true,
      track: {
        id: track.id,
        title: track.title,
        artist: track.artist,
        duration: track.duration,
        position: this.queue.length,
      },
    };
  }

  // Start playing the next track
  _playNext() {
    // Stop current ffmpeg if running
    this._stopFfmpeg();

    if (this.queue.length === 0) {
      // Queue empty — but a download might be in progress.
      // Wait up to 10s for a track to appear before giving up.
      if (this.downloadingSet.size > 0) {
        console.log(`[radio] queue empty, waiting for ${this.downloadingSet.size} pending download(s)...`);
        this.currentTrack = null;
        this.isPlaying = true; // stay "playing" so addToQueue triggers _playNext
        this._notifyWebhook("queue_low");

        let waited = 0;
        const waitInterval = setInterval(() => {
          waited += 500;
          if (this.queue.length > 0) {
            clearInterval(waitInterval);
            console.log(`[radio] track arrived after ${waited}ms wait`);
            this._playNext();
          } else if (waited >= 10000 || this.downloadingSet.size === 0) {
            clearInterval(waitInterval);
            if (this.queue.length > 0) {
              this._playNext();
            } else {
              this.isPlaying = false;
              this.currentTrack = null;
              console.log("[radio] queue empty after waiting, stopped");
              this._notifyWebhook("queue_empty");
            }
          }
        }, 500);
        return;
      }

      this.isPlaying = false;
      this.currentTrack = null;
      console.log("[radio] queue empty, stopped");
      this._notifyWebhook("queue_empty");
      return;
    }

    const track = this.queue.shift();
    track.startedAt = Date.now();
    this.currentTrack = track;
    this.isPlaying = true;

    console.log(`[radio] now playing: "${track.title}" by ${track.artist}`);

    // Check remaining queue and notify if low (< 5 songs)
    if (this.queue.length < 5) {
      this._notifyWebhook("queue_low");
    }

    // Use ffmpeg to stream the mp3 to all connected clients
    const volumeFilter = this.volume / 100;
    const args = [
      "-re", // read at native speed (real-time)
      "-i", track.filePath,
      "-af", `volume=${volumeFilter}`,
      "-f", "mp3",
      "-ab", "128k",
      "-ar", "44100",
      "-ac", "2",
      "pipe:1",
    ];

    this.ffmpegProc = spawn("ffmpeg", args);

    this.ffmpegProc.stdout.on("data", (chunk) => {
      // Broadcast to all connected clients
      for (const client of this.clients) {
        try {
          if (!client.destroyed) {
            client.write(chunk);
          } else {
            this.clients.delete(client);
          }
        } catch {
          this.clients.delete(client);
        }
      }
    });

    this.ffmpegProc.stderr.on("data", (d) => {
      // ffmpeg outputs progress to stderr, mostly noise
      const line = d.toString().trim();
      if (line.includes("Error") || line.includes("error")) {
        console.error(`[radio] ffmpeg: ${line}`);
      }
    });

    this.ffmpegProc.on("close", (code) => {
      console.log(`[radio] ffmpeg exited (code=${code}) for "${track.title}"`);
      this.ffmpegProc = null;

      // Play next track first, then clean up file async
      if (this.isPlaying) {
        this._playNext();
      }
      fs.unlink(track.filePath, () => {});
    });

    this.ffmpegProc.on("error", (err) => {
      console.error(`[radio] ffmpeg error: ${err.message}`);
      this.ffmpegProc = null;
      if (this.isPlaying) {
        this._playNext();
      }
      fs.unlink(track.filePath, () => {});
    });

    this.emit("trackChanged", this.getNowPlaying());
  }

  // Stop current ffmpeg process
  _stopFfmpeg() {
    if (this.ffmpegProc) {
      const proc = this.ffmpegProc;
      this.ffmpegProc = null;
      // Remove all listeners to prevent the close handler from triggering _playNext again
      proc.removeAllListeners("close");
      proc.removeAllListeners("error");
      proc.stdout.removeAllListeners("data");
      proc.stderr.removeAllListeners("data");
      try {
        proc.kill("SIGTERM");
      } catch {}
      // Clean up current track file
      if (this.currentTrack?.filePath) {
        try { fs.unlinkSync(this.currentTrack.filePath); } catch {}
      }
    }
  }

  // Skip current track
  skip() {
    if (!this.isPlaying) {
      return { ok: false, error: "Not playing" };
    }
    const skipped = this.currentTrack?.title || "Unknown";
    this._playNext();
    return { ok: true, skipped };
  }

  // Set volume (0-100)
  // Volume change takes effect on the next track.
  // For immediate effect, the web player can also adjust its own <audio> volume.
  setVolume(vol) {
    const v = Math.max(0, Math.min(100, Number(vol) || 80));
    this.volume = v;
    return { ok: true, volume: this.volume };
  }

  // Get current playing info
  getNowPlaying() {
    return {
      isPlaying: this.isPlaying,
      currentTrack: this.currentTrack
        ? {
            id: this.currentTrack.id,
            title: this.currentTrack.title,
            artist: this.currentTrack.artist,
            duration: this.currentTrack.duration,
            thumbnail: this.currentTrack.thumbnail,
            startedAt: this.currentTrack.startedAt || null,
          }
        : null,
      volume: this.volume,
      queueLength: this.queue.length,
      listeners: this.clients.size,
    };
  }

  // Get queue info
  getQueue() {
    return {
      currentTrack: this.currentTrack
        ? {
            id: this.currentTrack.id,
            title: this.currentTrack.title,
            artist: this.currentTrack.artist,
          }
        : null,
      queue: this.queue.map((t, i) => ({
        position: i + 1,
        id: t.id,
        title: t.title,
        artist: t.artist,
        duration: t.duration,
      })),
      total: this.queue.length,
    };
  }

  // Register a streaming client
  addClient(res) {
    this.clients.add(res);
    console.log(`[radio] client connected (${this.clients.size} total)`);

    res.on("close", () => {
      this.clients.delete(res);
      console.log(`[radio] client disconnected (${this.clients.size} total)`);
    });
  }

  // Set webhook URL for notifications
  setWebhook(url) {
    this.webhookUrl = url;
    return { ok: true, webhookUrl: url };
  }

  // Notify Crowbot via webhook
  async _notifyWebhook(event) {
    if (!this.webhookUrl) return;

    try {
      console.log(`[radio] webhook notify: ${event} -> ${this.webhookUrl}`);
      const body = {
        event,
        timestamp: new Date().toISOString(),
        now: this.getNowPlaying(),
      };

      await fetch(this.webhookUrl, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10000),
      });
    } catch (err) {
      console.error(`[radio] webhook error: ${err.message}`);
    }
  }

  // Clean up on shutdown
  destroy() {
    this._stopFfmpeg();
    this.isPlaying = false;
    this.currentTrack = null;

    // Close all client connections
    for (const client of this.clients) {
      try { client.end(); } catch {}
    }
    this.clients.clear();

    // Clean up temp files
    try {
      const files = fs.readdirSync(RADIO_DIR);
      for (const f of files) {
        try { fs.unlinkSync(path.join(RADIO_DIR, f)); } catch {}
      }
    } catch {}
  }
}

// Singleton instance
const radio = new Radio();

export default radio;
