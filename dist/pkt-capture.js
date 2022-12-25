"use strict";var E=Object.create;var n=Object.defineProperty;var B=Object.getOwnPropertyDescriptor;var C=Object.getOwnPropertyNames;var P=Object.getPrototypeOf,T=Object.prototype.hasOwnProperty;var w=(s,t)=>{for(var e in t)n(s,e,{get:t[e],enumerable:!0})},y=(s,t,e,o)=>{if(t&&typeof t=="object"||typeof t=="function")for(let i of C(t))!T.call(s,i)&&i!==e&&n(s,i,{get:()=>t[i],enumerable:!(o=B(t,i))||o.enumerable});return s};var x=(s,t,e)=>(e=s!=null?E(P(s)):{},y(t||!s||!s.__esModule?n(e,"default",{value:s,enumerable:!0}):e,s)),I=s=>y(n({},"__esModule",{value:!0}),s);var R={};w(R,{PktCapture:()=>c,PktCaptureAll:()=>a,deviceList:()=>d,findDevice:()=>M});module.exports=I(R);var h=x(require("cap")),v=require("net"),m=require("tiny-typed-emitter"),{findDevice:M,deviceList:d}=h.default.Cap,{Ethernet:L,PROTOCOL:k,IPV4:N,TCP:O}=h.default.decoders;var c=class extends m.TypedEmitter{c;#t;constructor(t){super(),this.c=new h.default.Cap,this.#t=Buffer.alloc(65535);let e=this.c.open(t,"tcp and src port 6040",10*1024*1024,this.#t),o=new b;this.c.setMinBytes&&this.c.setMinBytes(54),this.c.on("packet",(i,r)=>{if(e==="ETHERNET"){let g=L(this.#t);if(g.info.type===k.ETHERNET.IPV4){let f=N(this.#t,g.offset);if(f.info.protocol===k.IP.TCP){let u=f.info.totallen-f.hdrlen,p=O(this.#t,f.offset);if(u-=p.hdrlen,u){o.write(this.#t.subarray(p.offset,p.offset+u));let l=o.read();for(;l;)this.emit("packet",l),l=o.read()}}}}})}close(){this.c.close()}},a=class extends m.TypedEmitter{caps;constructor(t){super(),this.caps=new Map;for(let e of d())for(let o of e.addresses)if((0,v.isIPv4)(o.addr))try{let i=new c(e.name);i.on("packet",r=>this.emit("packet",r,e.name)),this.caps.set(e.name,i)}catch(i){t(`[meter-core/PktCaptureAll] ${i}`)}}close(){for(let t of this.caps.values())t.close()}},b=class{buffer;position;out;constructor(){this.buffer=null,this.position=0,this.out=[]}write(t){for(;t.length>0;){if(this.buffer){if(this.buffer.length<2){let i=this.buffer[0],r=(t[0]<<8)+i;this.buffer=Buffer.alloc(r),this.buffer[0]=i,this.position=1}let o=Math.min(t.length,this.buffer.length-this.position);t.copy(this.buffer,this.position,0,o),this.position+=o,this.position===this.buffer.length&&(this.out.push(this.buffer),this.buffer=null,this.position=0),t=t.subarray(o);continue}if(t.length<2){this.buffer=Buffer.from(t),this.position=t.length;break}let e=t.readUInt16LE(0);if(e>t.length){this.buffer=Buffer.alloc(e),t.copy(this.buffer),this.position=t.length;break}this.out.push(t.subarray(0,e)),t=t.subarray(e)}}read(){return this.out.shift()}};0&&(module.exports={PktCapture,PktCaptureAll,deviceList,findDevice});
