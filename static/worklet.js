class MicrophonePCM extends AudioWorkletProcessor {
  constructor() {
    super();
    this.chunk = new Float32Array(Math.max(128, Math.round(sampleRate * 0.02)));
    this.offset = 0;
    this.energy = 0;
  }

  process(inputs) {
    const channels = inputs[0];
    if (!channels || !channels.length) return true;
    const frames = channels[0].length;
    for (let i = 0; i < frames; i++) {
      let value = 0;
      for (const channel of channels) value += channel[i] || 0;
      value /= channels.length;
      this.chunk[this.offset++] = value;
      this.energy += value * value;
      if (this.offset === this.chunk.length) {
        // Explicit little-endian encoding, independent of the host's endianness.
        const buffer = new ArrayBuffer(this.chunk.length * 4);
        const view = new DataView(buffer);
        for (let j = 0; j < this.chunk.length; j++) view.setFloat32(j * 4, this.chunk[j], true);
        this.port.postMessage({ buffer, rms: Math.sqrt(this.energy / this.chunk.length) }, [buffer]);
        this.offset = 0;
        this.energy = 0;
      }
    }
    // Outputs remain silent: connecting to destination keeps Safari processing
    // without playing captured microphone audio through the Mac speakers.
    return true;
  }
}
registerProcessor('microphone-pcm', MicrophonePCM);
