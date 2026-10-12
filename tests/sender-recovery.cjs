const vm = require('node:vm');
const fs = require('node:fs');
const assert = require('node:assert/strict');
const source = fs.readFileSync(require('node:path').join(__dirname, '../static/app.js'), 'utf8');
function fixture() {
  const timers = new Map(); let next = 0; const sockets = []; const nodes = []; const contexts = [];
  const element = () => ({ listeners: {}, addEventListener(k, f) { this.listeners[k] = f; }, value: 0 });
  const elements = Object.fromEntries(['start','stop','status','details','level','connection-code'].map(k => [k, element()]));
  const track = { readyState: 'live', addEventListener(k,f) { this[k] = f; }, stop() { this.readyState = 'ended'; } };
  let requests = 0;
  class Socket { static OPEN=1; static CLOSING=2; static CLOSED=3; static CONNECTING=0;
    constructor() { this.readyState=0; this.bufferedAmount=0; this.sent=[]; sockets.push(this); }
    close() { this.readyState=3; } send(v) { this.sent.push(v); }
    ready() { this.readyState=1; this.onopen(); this.onmessage({data:'{"ready":true}'}); }
  }
  class Context { constructor() { this.state='running'; this.sampleRate=48000; this.audioWorklet={addModule:async()=>{}}; contexts.push(this); }
    resume() { this.state='running'; return Promise.resolve(); } close() { this.state='closed'; return Promise.resolve(); }
    createMediaStreamSource() { return {connect(){},disconnect(){}}; }
  }
  class Worklet { constructor() { this.port={}; nodes.push(this); } connect(){} disconnect(){} }
  const window={AudioContext:Context,isSecureContext:true,listeners:{},addEventListener(k,f){this.listeners[k]=f;}};
  const document={getElementById:k=>elements[k],listeners:{},addEventListener(k,f){this.listeners[k]=f;}};
  vm.runInNewContext(source,{window,document,navigator:{mediaDevices:{getUserMedia:async()=>{requests++; return {getTracks:()=>[track],getAudioTracks:()=>[track]};}}},location:{hash:'#token=test',protocol:'https:',href:'https://example.com/',pathname:'/',search:''},history:{replaceState(){}},URL,URLSearchParams,WebSocket:Socket,AudioWorkletNode:Worklet,Date,setTimeout:f=>{timers.set(++next,f);return next;},clearTimeout:k=>timers.delete(k),setInterval:f=>{return ++next;},clearInterval(){}});
  return {elements,track,sockets,nodes,contexts,window,requests:()=>requests,timers, async start(){await elements.start.listeners.click(); await Promise.resolve();}, async timer(){const [k,f]=timers.entries().next().value;timers.delete(k);f(); await Promise.resolve();}};
}
(async()=>{
  const a=fixture(); await a.start(); assert.equal(a.sockets.length,1); a.sockets[0].ready();
  a.nodes[0].port.onmessage({data:{rms:0.1,buffer:new ArrayBuffer(4)}}); assert.equal(a.sockets[0].sent.length,2);
  const stale=a.sockets[0]; stale.readyState=3; stale.onclose();
  a.nodes[0].port.onmessage({data:{rms:0.2,buffer:new ArrayBuffer(4)}}); assert.equal(a.elements.level.value,0.8);
  await a.timer(); assert.equal(a.sockets.length,2); a.sockets[1].ready(); stale.onclose(); assert.equal(a.timers.size,0);
  assert.equal(a.requests(),1); assert.equal(a.track.readyState,'live'); assert.equal(a.nodes.length,1);
  a.sockets[1].bufferedAmount=400000; a.nodes[0].port.onmessage({data:{rms:0,buffer:new ArrayBuffer(4)}});
  assert.equal(a.track.readyState,'live'); a.elements.stop.listeners.click(); assert.equal(a.timers.size,0); assert.equal(a.track.readyState,'ended');
  a.window.listeners.focus(); assert.equal(a.sockets.length,2);
  const b=fixture(); await b.start(); b.sockets[0].ready(); b.contexts[0].state='suspended'; await b.contexts[0].onstatechange(); await b.timer(); b.sockets[1].ready(); assert.equal(b.requests(),1);
  b.track.readyState='ended'; b.track.ended(); assert.equal(b.timers.size,0); assert.equal(b.elements.stop.disabled,true);
  const c=fixture(); await c.start(); c.sockets[0].ready(); c.window.listeners.pagehide(); c.window.listeners.focus(); assert.equal(c.track.readyState,'ended'); assert.equal(c.sockets.length,1);
  const d=fixture(); await d.start(); d.sockets[0].ready(); d.sockets[0].onmessage({data:'{"error":true,"reason":"busy"}'}); assert.equal(d.track.readyState,'ended'); assert.equal(d.timers.size,0);
  console.log('PASS: live-stream reconnect, stale events, local level, backpressure, Stop, context resume, ended track, pagehide, fatal busy');
})().catch(e=>{console.error(e);process.exitCode=1;});
