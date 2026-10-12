'use strict';

(() => {
  const startButton = document.getElementById('start');
  const stopButton = document.getElementById('stop');
  const status = document.getElementById('status');
  const details = document.getElementById('details');
  const level = document.getElementById('level');
  const codeInput = document.getElementById('connection-code');
  // Remove the fragment from browser history; keep the secret only in memory.
  let token = new URLSearchParams(location.hash.slice(1)).get('token') || '';
  codeInput.value = token;
  if (location.hash) history.replaceState(null, '', location.pathname + location.search);
  let active = null;

  function current(session) { return active === session && !session.closed; }
  function finish(session, message) {
    if (!session || session.closed) return;
    session.closed = true;
    clearTimeout(session.timeout);
    clearTimeout(session.retryTimer);
    clearInterval(session.healthTimer);
    if (session.node) { session.node.port.onmessage = null; session.node.disconnect(); }
    if (session.source) session.source.disconnect();
    if (session.stream) session.stream.getTracks().forEach(track => track.stop());
    if (session.socket) session.socket.close();
    if (session.context) {
      session.context.onstatechange = null;
      session.context.close().catch(() => {});
    }
    if (active === session) {
      active = null;
      level.value = 0;
      startButton.disabled = !token;
      stopButton.disabled = true;
      codeInput.disabled = false;
      status.textContent = message;
      details.textContent = '麥克風已停止。重新開始必須再次按下開始按鈕。';
    }
  }

  function waiting(message) {
    status.textContent = message;
    details.textContent = '麥克風仍開啟，正在自動恢復；按「停止」可結束收音。';
  }
  function recover(session, message) {
    if (!current(session) || session.retryTimer) return;
    session.ready = false;
    session.transportClosing = true;
    clearTimeout(session.timeout);
    if (session.socket && session.socket.readyState < WebSocket.CLOSING) session.socket.close();
    if (++session.failures > 12) return finish(session, '多次連線失敗，請確認連線碼、Windows 接收器及網路後重新開始。');
    waiting(message);
    const delay = Math.min(10000, 500 * 2 ** (session.failures - 1));
    session.retryTimer = setTimeout(() => {
      session.retryTimer = null;
      connect(session);
    }, delay);
  }
  function setupGraph(session) {
    if (session.node) return;
    session.node = new AudioWorkletNode(session.context, 'microphone-pcm', { numberOfInputs: 1, numberOfOutputs: 1, outputChannelCount: [1] });
    session.node.onprocessorerror = () => finish(session, '音訊處理已中斷，請重新開始。');
    session.node.port.onmessage = ({ data }) => {
      if (!current(session)) return;
      level.value = Math.min(1, data.rms * 4);
      const socket = session.socket;
      // Never retain chunks while disconnected: reconnect must send live audio only.
      if (!session.ready || !socket || socket.readyState !== WebSocket.OPEN) return;
      if (socket.bufferedAmount > 384000) return recover(session, '網路傳送較慢，正在重新連線…');
      try { socket.send(data.buffer); }
      catch (_) { recover(session, '音訊傳送中斷，正在重新連線…'); }
    };
    session.source = session.context.createMediaStreamSource(session.stream);
    session.source.connect(session.node);
    session.node.connect(session.context.destination);
  }
  function connect(session) {
    if (!current(session) || !session.initialized) return;
    if (!session.stream.getAudioTracks().some(track => track.readyState === 'live')) return finish(session, '麥克風已中斷，請重新開始。');
    if (session.context.state !== 'running') { waiting('瀏覽器暫停音訊，請回到此分頁以自動恢復…'); return; }
    // Wait for the previous transport to close before creating another one.
    if (session.socket && session.socket.readyState !== WebSocket.CLOSED) {
      if (!session.transportClosing) return;
      return recover(session, '正在等待舊連線關閉…');
    }
    const url = new URL('/ws', location.href);
    url.protocol = 'wss:';
    url.searchParams.set('token', token);
    session.transportClosing = false;
    const socket = session.socket = new WebSocket(url);
    const valid = () => current(session) && session.socket === socket;
    waiting('正在連接 Windows…');
    session.timeout = setTimeout(() => {
      if (valid()) recover(session, '連線逾時，正在重新連線…');
    }, 15000);
    socket.onopen = () => {
      if (!valid() || session.retryTimer) return;
      try { socket.send(JSON.stringify({ sampleRate: session.context.sampleRate })); }
      catch (_) { recover(session, '連線中斷，正在重新連線…'); }
    };
    socket.onerror = () => { if (valid()) recover(session, '連線失敗，正在重新連線…'); };
    socket.onclose = () => { if (valid()) recover(session, '連線中斷，正在重新連線…'); };
    socket.onmessage = event => {
      if (!valid() || session.retryTimer || socket.readyState !== WebSocket.OPEN) return;
      try {
        if (typeof event.data !== 'string') throw new Error('invalid response');
        const message = JSON.parse(event.data);
        if (message.error) {
          if (['auth', 'unauthorized', 'busy', 'invalid_token'].includes(message.reason)) return finish(session, '接收器拒絕連線，請確認連線碼或是否有其他分頁正在傳送。');
          return recover(session, 'Windows 接收器暫時無法收音，正在重新連線…');
        }
        if (message.ready !== true || session.ready) return;
        clearTimeout(session.timeout);
        setupGraph(session);
        session.ready = true;
        // A stable connection resets the retry budget, not a brief handshake.
        session.connectedAt = Date.now();
        status.textContent = '正在傳送麥克風到 Windows';
        details.textContent = `單聲道 · ${session.context.sampleRate.toLocaleString()} Hz · 請保持這個分頁開啟`;
      } catch (_) { finish(session, '接收器回應或音訊處理發生錯誤，請重新開始。'); }
    };
  }
  async function maintain(session) {
    if (!current(session) || !session.initialized) return;
    if (session.context.state === 'closed') return finish(session, '瀏覽器已關閉音訊，請重新開始。');
    if (session.context.state !== 'running') {
      if (session.ready) recover(session, '瀏覽器暫停音訊，正在嘗試恢復…');
      waiting('瀏覽器暫停音訊，請回到此分頁以自動恢復…');
      if (!session.resuming) {
        session.resuming = true;
        try { await session.context.resume(); } catch (_) { /* Gesture may be required. */ }
        finally { session.resuming = false; }
      }
    }
    if (!current(session)) return;
    if (session.ready && Date.now() - session.connectedAt > 30000) session.failures = 0;
    if (session.context.state === 'running' && !session.ready && !session.retryTimer) connect(session);
  }
  async function start() {
    if (active || !token) return;
    const session = { closed: false, failures: 0, ready: false };
    active = session;
    startButton.disabled = true;
    stopButton.disabled = false;
    codeInput.disabled = true;
    status.textContent = '正在要求麥克風權限…';
    try {
      const AudioContextClass = window.AudioContext || window.webkitAudioContext;
      if (!window.isSecureContext || location.protocol !== 'https:') throw new Error('請使用提供的 HTTPS 網址開啟此頁面。');
      if (!navigator.mediaDevices?.getUserMedia || !AudioContextClass) throw new Error('這個瀏覽器不支援麥克風擷取，請更新 Safari 或使用新版 Chrome。');
      session.context = new AudioContextClass({ sampleRate: 48000 });
      // Start resume within the user gesture, but do not discard live capture on suspension.
      session.context.resume().catch(() => {});
      session.stream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true }, video: false });
      if (!current(session)) { session.stream.getTracks().forEach(track => track.stop()); return; }
      if (!session.context.audioWorklet) throw new Error('這個瀏覽器不支援 AudioWorklet，請更新 Safari 或使用新版 Chrome。');
      session.stream.getAudioTracks().forEach(track => track.addEventListener('ended', () => finish(session, '麥克風已中斷，請重新開始。')));
      await session.context.audioWorklet.addModule('/worklet.js');
      if (!current(session)) return;
      session.initialized = true;
      session.context.onstatechange = () => maintain(session);
      session.healthTimer = setInterval(() => maintain(session), 2000);
      maintain(session);
    } catch (error) {
      finish(session, error.name === 'NotAllowedError' ? '未取得麥克風權限。請允許此網站使用麥克風後再試一次。' : error.name === 'NotFoundError' ? '找不到可用的麥克風。' : error.message || '無法啟動麥克風。');
    }
  }
  startButton.addEventListener('click', start);
  codeInput.addEventListener('input', () => {
    const value = codeInput.value.trim();
    token = value;
    if (/^https:\/\//i.test(value)) {
      try { token = new URLSearchParams(new URL(value).hash.slice(1)).get('token') || ''; }
      catch (_) { token = ''; }
    }
    startButton.disabled = !token;
    status.textContent = token ? '連線碼已填入，請按開始' : '請貼上連線碼';
    details.textContent = '按下開始後才會要求麥克風權限並驗證連線碼。';
  });
  stopButton.addEventListener('click', () => finish(active, '已停止'));
  window.addEventListener('pagehide', () => finish(active, '已停止'));
  window.addEventListener('focus', () => { if (active) maintain(active); });
  document.addEventListener('visibilitychange', () => { if (!document.hidden && active) maintain(active); });
  if (!token) {
    startButton.disabled = true;
    status.textContent = '請貼上連線碼';
    details.textContent = '可貼上連線碼，或包含 #token= 的完整收音連結。';
  }
})();
