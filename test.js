const { PktCaptureAll, PktCaptureMode } = require("meter-core/pkt-capture");
const capture = new PktCaptureAll(PktCaptureMode.MODE_PCAP, 6040);
capture.on("packet", (buf) => {
  console.log(buf.toString("hex"));
});
