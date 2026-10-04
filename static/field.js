const canvas = document.getElementById("field");
const ctx = canvas.getContext("2d");
const pointer = { x: window.innerWidth / 2, y: window.innerHeight / 2, active: false };
let dots = [];

function resize() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  const gap = 28;
  dots = [];
  for (let y = 18; y < canvas.height; y += gap) {
    for (let x = 18; x < canvas.width; x += gap) {
      dots.push({ x, y, h: 0 });
    }
  }
}

window.addEventListener("resize", resize);
window.addEventListener("pointermove", (event) => {
  pointer.x = event.clientX;
  pointer.y = event.clientY;
  pointer.active = true;
});
window.addEventListener("pointerleave", () => {
  pointer.active = false;
});
resize();

function frame() {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  for (const dot of dots) {
    const dx = pointer.x - dot.x;
    const dy = pointer.y - dot.y;
    const dist = Math.hypot(dx, dy);
    const target = pointer.active ? Math.max(0, 1 - dist / 180) : 0;
    dot.h += (target - dot.h) * 0.12;
    const size = 1.1 + dot.h * 2.4;
    ctx.beginPath();
    ctx.fillStyle = `rgba(226, 226, 226, ${0.16 + dot.h * 0.7})`;
    ctx.arc(dot.x - dx * dot.h * 0.18, dot.y - dy * dot.h * 0.18, size, 0, Math.PI * 2);
    ctx.fill();
  }
  requestAnimationFrame(frame);
}
frame();
