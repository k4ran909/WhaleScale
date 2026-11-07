// The ASCII aquarium: hammerheads, a slim shark and a reef fish drawn as a
// mosaic of glyph tiles on porcelain, with drifting plankton and a soft
// clearing in the middle for the sign-in card. Ported from the standalone
// hero page (index.html) as is, except: it draws into a given canvas,
// stops cleanly (startAquarium returns a stop function), uses the system
// monospace font (the console's security policy allows no outside fonts),
// and can render a single still frame for reduced motion.

const CELL = 13; // px per mosaic cell
const NODES = 28; // spine resolution
const BG = [246, 246, 243]; // porcelain
const BG_STR = "rgb(246,246,243)";
const MONO = 'ui-monospace, "Cascadia Mono", Consolas, "SF Mono", Menlo, monospace';
const RAMP = [".", ":", "'", "`", ",", "-", "~", "=", "+", ";",
  "o", "l", "t", "s", "v", "y", "0", "1", "5",
  "k", "d", "h", "G", "D", "Z",
  "%", "8", "&", "#", "B", "@", "W", "M"];
const HALO = [".", "·", ":", "'", ","];
const ACCENTS = [[200, 158, 166], [158, 182, 140], [150, 170, 200]]; // rose · olive · ice
const LIGHT_X = -0.55, LIGHT_Y = -0.835; // light from above-left
const SIM_DT = 1 / 120;

// tone ramps: darkness 0 → 1 (light tile → deep shadow)
type Stop = [number, number, number, number];
const SHARK_STOPS: Stop[] = [[0, 222, 222, 220], [0.35, 160, 160, 160], [0.62, 104, 104, 106], [0.8, 74, 74, 74], [1, 52, 52, 54]];
const SEPIA_STOPS: Stop[] = [[0, 226, 220, 210], [0.35, 176, 160, 138], [0.6, 154, 138, 106], [0.8, 138, 122, 104], [1, 92, 80, 66]];

/* ── helpers ── */
const clamp = (v: number, a: number, b: number) => (v < a ? a : v > b ? b : v);
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const smooth = (a: number, b: number, x: number) => {
  const t = clamp((x - a) / (b - a), 0, 1);
  return t * t * (3 - 2 * t);
};
function mulberry32(a: number) {
  return function () {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
function hash(x: number, y: number, z: number) {
  let h = (x * 374761393 + y * 668265263 + z * 1274126177) | 0;
  h = Math.imul(h ^ (h >>> 13), 1274126177);
  h ^= h >>> 16;
  return (h >>> 0) / 4294967296;
}
// smooth value noise over time per cell (drives the shimmer)
function tnoise(x: number, y: number, t: number) {
  const k = Math.floor(t), f = t - k, s = f * f * (3 - 2 * f);
  return lerp(hash(x, y, k), hash(x, y, k + 1), s);
}
function angDiff(a: number, b: number) {
  let d = b - a;
  while (d > Math.PI) d -= 2 * Math.PI;
  while (d < -Math.PI) d += 2 * Math.PI;
  return d;
}
function buildLUT(stops: Stop[]) {
  const lut = new Uint8Array(256 * 3);
  for (let i = 0; i < 256; i++) {
    const t = i / 255;
    let j = 0;
    while (j < stops.length - 2 && t > stops[j + 1][0]) j++;
    const a = stops[j], b = stops[j + 1], u = clamp((t - a[0]) / (b[0] - a[0]), 0, 1);
    lut[i * 3] = lerp(a[1], b[1], u);
    lut[i * 3 + 1] = lerp(a[2], b[2], u);
    lut[i * 3 + 2] = lerp(a[3], b[3], u);
  }
  return lut;
}
const SHARK_LUT = buildLUT(SHARK_STOPS), SEPIA_LUT = buildLUT(SEPIA_STOPS);
type Profile = [number, number][];
function prof(P: Profile, s: number) {
  if (s <= P[0][0]) return P[0][1];
  for (let i = 1; i < P.length; i++)
    if (s <= P[i][0]) {
      const a = P[i - 1], b = P[i];
      return lerp(a[1], b[1], (s - a[0]) / (b[0] - a[0]));
    }
  return P[P.length - 1][1];
}
// signed distance to a triangle (Inigo Quilez)
function sdTri(px: number, py: number, ax: number, ay: number, bx: number, by: number, cx: number, cy: number) {
  const e0x = bx - ax, e0y = by - ay, e1x = cx - bx, e1y = cy - by, e2x = ax - cx, e2y = ay - cy;
  const v0x = px - ax, v0y = py - ay, v1x = px - bx, v1y = py - by, v2x = px - cx, v2y = py - cy;
  const c0 = clamp((v0x * e0x + v0y * e0y) / (e0x * e0x + e0y * e0y), 0, 1);
  const c1 = clamp((v1x * e1x + v1y * e1y) / (e1x * e1x + e1y * e1y), 0, 1);
  const c2 = clamp((v2x * e2x + v2y * e2y) / (e2x * e2x + e2y * e2y), 0, 1);
  const q0x = v0x - e0x * c0, q0y = v0y - e0y * c0;
  const q1x = v1x - e1x * c1, q1y = v1y - e1y * c1;
  const q2x = v2x - e2x * c2, q2y = v2y - e2y * c2;
  const s = Math.sign(e0x * e2y - e0y * e2x);
  const dx = Math.min(q0x * q0x + q0y * q0y, q1x * q1x + q1y * q1y, q2x * q2x + q2y * q2y);
  const dy = Math.min(s * (v0x * e0y - v0y * e0x), s * (v1x * e1y - v1y * e1x), s * (v2x * e2y - v2y * e2x));
  return -Math.sqrt(dx) * Math.sign(dy);
}

/* ── anatomy ──
   Each shape fn receives spine coords: s (0 = snout, 1 = tail root),
   d (signed lateral px, + = creature's right) and returns sdf in px plus
   a darkness value via OUT. */
const OUT = { dark: 0 };

const HAMMER_BODY: Profile = [[-0.01, 0.03], [0.04, 0.05], [0.1, 0.07], [0.2, 0.095], [0.3, 0.105], [0.45, 0.095], [0.6, 0.07], [0.75, 0.045], [0.88, 0.026], [1.0, 0.016]];
const SLIM_BODY: Profile = [[-0.04, 0.0], [0.0, 0.024], [0.07, 0.056], [0.18, 0.08], [0.32, 0.086], [0.5, 0.07], [0.7, 0.045], [0.86, 0.024], [1.0, 0.014]];
const REEF_BODY: Profile = [[-0.03, 0.0], [0.0, 0.03], [0.08, 0.07], [0.22, 0.1], [0.36, 0.104], [0.55, 0.085], [0.72, 0.05], [0.85, 0.024], [1.0, 0.016]];

function bodyShade(c: Creature, d: number, hb: number, fx: number, fy: number) {
  const u = clamp(d / hb, -1, 1);
  const ridgeOff = c.roll * 0.45; // dorsal ridge slides into the bank
  const r = (u - ridgeOff) / 0.38, ridge = Math.exp(-r * r);
  const side = d >= 0 ? 1 : -1;
  const lightDot = fy * side * -LIGHT_X + -fx * side * -LIGHT_Y; // screen normal of this flank · light
  let dark = 0.58 + 0.26 * ridge + 0.1 * (1 - u * u);
  dark -= 0.2 * lightDot * Math.abs(u); // flank facing the light is brighter
  dark += 0.12 * c.roll * u; // roll darkens the lower flank
  if (lightDot > 0.35 && Math.abs(u) > 0.35 && Math.abs(u) < 0.75) dark -= 0.22; // wet specular band
  if (Math.abs(u) > 0.82) dark -= 0.14; // diffuse rim
  return dark;
}

function shapeHammer(c: Creature, s: number, d: number, fx: number, fy: number) {
  const L = c.L, ad = Math.abs(d), side = d >= 0 ? 1 : -1;
  const sl = s * L;
  let best = 1e9, dark = 0.5;

  // torso
  const hb = prof(HAMMER_BODY, s) * L;
  const sdB = Math.max(ad - hb, (-0.015 - s) * L, (s - 1.0) * L);
  if (sdB < best) {
    best = sdB;
    dark = bodyShade(c, d, hb, fx, fy);
  }

  // cephalofoil: wide flat T-shaped hammer, tips swept back
  const H = 0.2 * L, q = Math.min(1, ad / H);
  const front = -0.035 + 0.045 * q * q, back = 0.045 + 0.04 * q * q;
  const sdH = Math.max((front - s) * L, (s - back) * L, ad - H);
  if (sdH < best) {
    best = sdH;
    dark = 0.56 + 0.16 * (1 - q) - 0.12 * ((s - front) / (back - front));
    if (q > 0.88) dark = 0.92; // eyes at the lobe tips
  }

  // pectoral fins, swept back; the inner fin foreshortens during a bank
  const inner = side * Math.sign(c.turn || 1) > 0;
  const span = (0.27 - ((inner ? 0.08 : 0.015) * Math.abs(c.roll)) / 0.7) * L;
  const sdP = sdTri(sl, ad, 0.17 * L, 0.06 * L, 0.47 * L, span, 0.32 * L, 0.07 * L);
  if (sdP < best) {
    best = sdP;
    dark = 0.36 + 0.22 * clamp(1 - (ad - hb) / (span - hb), 0, 1) + (inner ? 0.08 : -0.04);
  }

  // pelvic fins
  const sdV = sdTri(sl, ad, 0.58 * L, 0.04 * L, 0.73 * L, 0.1 * L, 0.67 * L, 0.04 * L);
  if (sdV < best) {
    best = sdV;
    dark = 0.42;
  }

  // heterocercal caudal fin: long upper lobe, short lower lobe
  const dl = d * c.lobeSide;
  const sdU = sdTri(sl, dl, 0.84 * L, 0.0, 1.2 * L, 0.15 * L, 0.98 * L, -0.01 * L);
  if (sdU < best) {
    best = sdU;
    dark = 0.5 - 0.15 * clamp((s - 0.95) * 5, 0, 1);
  }
  const sdL = sdTri(sl, -dl, 0.88 * L, 0.0, 1.07 * L, 0.09 * L, 0.98 * L, 0.0);
  if (sdL < best) {
    best = sdL;
    dark = 0.44;
  }

  // tall dorsal fin seen from above: dense dark ridge
  if (best < 0 && s > 0.3 && s < 0.5) {
    const ridgeD = d - c.roll * 0.45 * hb;
    const w = 0.022 * L * (1 - Math.abs(s - 0.4) / 0.1);
    if (Math.abs(ridgeD) < w) dark += 0.3;
  }
  // gill slits
  if (best < 0 && s > 0.13 && s < 0.2 && ad > hb * 0.55 && ((sl / (0.012 * L)) | 0) % 2 === 0) dark += 0.12;

  OUT.dark = dark;
  return best;
}

function shapeSlim(c: Creature, s: number, d: number, fx: number, fy: number) {
  const L = c.L, ad = Math.abs(d), side = d >= 0 ? 1 : -1, sl = s * L;
  let best = 1e9, dark = 0.5;
  const hb = prof(SLIM_BODY, s) * L;
  const sdB = Math.max(ad - hb, (-0.04 - s) * L, (s - 1.0) * L);
  if (sdB < best) {
    best = sdB;
    dark = bodyShade(c, d, hb, fx, fy);
    if (s < 0.06) dark += 0.08;
  }
  const inner = side * Math.sign(c.turn || 1) > 0;
  const span = (0.21 - ((inner ? 0.06 : 0.01) * Math.abs(c.roll)) / 0.7) * L;
  const sdP = sdTri(sl, ad, 0.18 * L, 0.05 * L, 0.44 * L, span, 0.3 * L, 0.065 * L);
  if (sdP < best) {
    best = sdP;
    dark = 0.4 + (inner ? 0.06 : -0.04);
  }
  const dl = d * c.lobeSide;
  const sdU = sdTri(sl, dl, 0.85 * L, 0.0, 1.18 * L, 0.14 * L, 0.98 * L, -0.008 * L);
  if (sdU < best) {
    best = sdU;
    dark = 0.48;
  }
  const sdL = sdTri(sl, -dl, 0.9 * L, 0.0, 1.07 * L, 0.075 * L, 0.98 * L, 0.0);
  if (sdL < best) {
    best = sdL;
    dark = 0.42;
  }
  if (best < 0 && s > 0.32 && s < 0.48 && Math.abs(d - c.roll * 0.45 * hb) < 0.02 * L) dark += 0.28;
  OUT.dark = dark;
  return best;
}

function shapeReef(c: Creature, s: number, d: number, fx: number, fy: number) {
  const L = c.L, sl = s * L;
  let best = 1e9, dark = 0.5;
  const hb = prof(REEF_BODY, s) * L;
  const sdB = Math.max(Math.abs(d) - hb, (-0.03 - s) * L, (s - 1.0) * L);
  if (sdB < best) {
    best = sdB;
    dark = bodyShade(c, d, hb, fx, fy);
    dark += 0.1 * (Math.sin(s * 34) > 0.55 ? 1 : 0); // faint scale bands
    if (s < 0.1 && Math.abs(d) > hb * 0.35 && Math.abs(d) < hb * 0.75 && s > 0.05) dark = 0.95; // eye
  }
  const sdP = sdTri(sl, Math.abs(d), 0.24 * L, 0.06 * L, 0.4 * L, 0.15 * L, 0.33 * L, 0.07 * L);
  if (sdP < best) {
    best = sdP;
    dark = 0.34;
  }
  // forked tail (symmetric)
  const sdT1 = sdTri(sl, d, 0.84 * L, 0.0, 1.16 * L, 0.15 * L, 1.0 * L, 0.0);
  const sdT2 = sdTri(sl, -d, 0.84 * L, 0.0, 1.16 * L, 0.15 * L, 1.0 * L, 0.0);
  const sdT = Math.min(sdT1, sdT2);
  if (sdT < best) {
    best = sdT;
    dark = 0.42 - 0.12 * clamp((s - 0.98) * 6, 0, 1);
  }
  OUT.dark = dark;
  return best;
}

type ShapeFn = (c: Creature, s: number, d: number, fx: number, fy: number) => number;
interface Kind {
  shape: ShapeFn;
  lut: Uint8Array;
  lenK: number;
  speedK: number;
  waveF: number;
  waveAmp: number;
  margin: number;
}
const KINDS: Record<string, Kind> = {
  hammer: { shape: shapeHammer, lut: SHARK_LUT, lenK: 0.62, speedK: 0.12, waveF: 0.5, waveAmp: 0.055, margin: 0.33 },
  slim: { shape: shapeSlim, lut: SEPIA_LUT, lenK: 0.42, speedK: 0.17, waveF: 0.85, waveAmp: 0.06, margin: 0.27 },
  reef: { shape: shapeReef, lut: SEPIA_LUT, lenK: 0.22, speedK: 0.2, waveF: 1.4, waveAmp: 0.075, margin: 0.2 },
};

interface View {
  W: number;
  H: number;
  DPR: number;
  cols: number;
  rows: number;
}

/* ── creature ── */
class Creature {
  k: Kind;
  rng: () => number;
  z0: number;
  nodes = new Float32Array(NODES * 2);
  state: "wait" | "swim" = "wait";
  wait = 0;
  turn = 0;
  roll = 0;
  burst = 0;
  burstT = 0;
  phase = 0;
  lobeSide: number;
  z = 0;
  scale = 0;
  L = 0;
  base = 0;
  speed = 0;
  turnBias = 0;
  ta1 = 0; tw1 = 0; tp1 = 0;
  ta2 = 0; tw2 = 0; tp2 = 0;
  age = 0;
  x = 0;
  y = 0;
  heading = 0;
  entered = false;
  bbox = { x0: 0, y0: 0, x1: 0, y1: 0 };

  constructor(kind: string, seed: number, z: number) {
    this.k = KINDS[kind];
    this.rng = mulberry32(seed);
    this.z0 = z;
    this.lobeSide = this.rng() < 0.5 ? -1 : 1;
  }
  spawn(view: View, initial: { x: number; y: number; h: number } | null) {
    const r = this.rng, { W, H } = view, md = Math.min(W, H);
    this.z = clamp(this.z0 + (r() - 0.5) * 0.18, 0.05, 1);
    this.scale = 0.58 + 0.6 * this.z;
    this.L = md * this.k.lenK * this.scale * (0.9 + 0.2 * r());
    this.base = md * this.k.speedK * (0.55 + 0.6 * this.z); // closer swims faster across the screen
    this.speed = this.base;
    this.turnBias = (r() - 0.5) * 0.36;
    this.ta1 = 0.1 + 0.16 * r(); this.tw1 = 0.18 + 0.25 * r(); this.tp1 = r() * 6.283;
    this.ta2 = 0.05 + 0.08 * r(); this.tw2 = 0.5 + 0.4 * r(); this.tp2 = r() * 6.283;
    this.phase = r() * 6.283;
    this.age = 0;
    this.burst = 0;
    this.burstT = 0;
    this.turn = 0;
    this.roll = 0;
    if (initial) {
      this.x = initial.x * W;
      this.y = initial.y * H;
      this.heading = initial.h;
      this.entered = true;
    } else {
      const edge = (r() * 4) | 0, m = this.L * 0.12;
      if (edge === 0) { this.x = -m; this.y = H * (0.1 + 0.8 * r()); }
      else if (edge === 1) { this.x = W + m; this.y = H * (0.1 + 0.8 * r()); }
      else if (edge === 2) { this.x = W * (0.1 + 0.8 * r()); this.y = -m; }
      else { this.x = W * (0.1 + 0.8 * r()); this.y = H + m; }
      const tx = W * (0.2 + 0.6 * r()), ty = H * (0.2 + 0.6 * r());
      this.heading = Math.atan2(ty - this.y, tx - this.x) + (r() - 0.5) * 0.5;
      this.entered = false;
    }
    this.state = "swim";
    this.computeSpine();
  }
  update(dt: number, t: number, view: View) {
    const { W, H } = view;
    if (this.state === "wait") {
      this.wait -= dt;
      if (this.wait <= 0) this.spawn(view, null);
      return;
    }
    const r = this.rng;
    this.age += dt;

    // variable speed: occasional bursts, then languid glides
    if (this.burstT <= 0 && r() < dt * 0.07) this.burstT = 1.0 + 1.6 * r();
    const target = this.burstT > 0 ? 1 : 0;
    this.burstT -= dt;
    this.burst += (target - this.burst) * Math.min(1, dt * (target > this.burst ? 1.6 : 0.5));
    this.speed = this.base * (0.72 + 0.9 * this.burst);

    // curved / orbiting path
    let desired = this.turnBias + this.ta1 * Math.sin(this.tw1 * t + this.tp1) + this.ta2 * Math.sin(this.tw2 * t + this.tp2);
    const inside = this.x > 30 && this.x < W - 30 && this.y > 30 && this.y < H - 30;
    if (inside) this.entered = true;
    if (!this.entered) {
      desired += 1.2 * angDiff(this.heading, Math.atan2(H / 2 - this.y, W / 2 - this.x));
    } else if (this.age > 22) {
      // time to leave: drift toward the nearest edge
      const ex = this.x < W / 2 ? -W : 2 * W, ey = this.y < H / 2 ? -H : 2 * H;
      const ax = Math.abs(this.x - W / 2) / W > Math.abs(this.y - H / 2) / H ? Math.atan2(0, ex - this.x) : Math.atan2(ey - this.y, 0);
      desired = 0.6 * angDiff(this.heading, ax) + 0.4 * desired;
    }
    desired = clamp(desired, -0.55, 0.55);
    this.turn += (desired - this.turn) * Math.min(1, dt * 1.2);
    this.heading += this.turn * dt;

    // banking: roll into the turn like an aircraft
    const rollT = clamp(this.turn * 1.5, -0.7, 0.7);
    this.roll += (rollT - this.roll) * Math.min(1, dt * 1.5);

    this.x += Math.cos(this.heading) * this.speed * dt;
    this.y += Math.sin(this.heading) * this.speed * dt;

    const sp = this.speed / this.base;
    this.phase += dt * 6.2832 * this.k.waveF * (0.55 + 0.55 * sp);
    this.computeSpine();

    // left the tank? wait, then re-enter from another edge
    if (this.entered) {
      const b = this.bbox;
      if (b.x1 < 0 || b.x0 > W || b.y1 < 0 || b.y0 > H) {
        this.state = "wait";
        this.wait = 1.2 + 3.5 * r();
      }
    } else if (this.age > 25) {
      this.state = "wait";
      this.wait = 0.5;
    }
  }
  computeSpine() {
    const n = NODES, L = this.L, ds = L / (n - 1), nd = this.nodes;
    const kap = clamp(this.turn / Math.max(this.speed, 1), -1.4 / L, 1.4 / L);
    const amp0 = L * this.k.waveAmp * (0.7 + 0.5 * this.burst);
    let x = this.x, y = this.y;
    const cx = new Float32Array(n), cy = new Float32Array(n), ang = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      const s = i / (n - 1);
      ang[i] = this.heading - kap * s * L; // body trails along the turning arc
      if (i > 0) {
        x -= Math.cos(ang[i]) * ds;
        y -= Math.sin(ang[i]) * ds;
      }
      cx[i] = x;
      cy[i] = y;
    }
    let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
    for (let i = 0; i < n; i++) {
      const s = i / (n - 1);
      // sinusoidal body wave head → tail; amplitude grows toward the tail, tail lags further
      const lag = s > 0.72 ? (s - 0.72) * 1.6 : 0;
      const a = amp0 * (0.13 + s * s * 1.05);
      const off = a * Math.sin(this.phase - 6.2832 * 0.8 * s - lag);
      const nx = -Math.sin(ang[i]), ny = Math.cos(ang[i]);
      const px = cx[i] + nx * off, py = cy[i] + ny * off;
      nd[i * 2] = px;
      nd[i * 2 + 1] = py;
      if (px < x0) x0 = px;
      if (px > x1) x1 = px;
      if (py < y0) y0 = py;
      if (py > y1) y1 = py;
    }
    const m = this.k.margin * L;
    this.bbox = { x0: x0 - m, y0: y0 - m, x1: x1 + m, y1: y1 + m };
  }
}

// nearest spine segment → (s, signed lateral d, forward dir)
let PS = 0, PD = 0, PFX = 1, PFY = 0;
function project(c: Creature, px: number, py: number) {
  const nd = c.nodes, n = NODES;
  let best = 1e18;
  for (let j = 0; j < n - 1; j++) {
    const ax = nd[2 * j], ay = nd[2 * j + 1];
    const ex = nd[2 * j + 2] - ax, ey = nd[2 * j + 3] - ay;
    const el2 = ex * ex + ey * ey || 1e-6;
    let u = ((px - ax) * ex + (py - ay) * ey) / el2;
    if (j > 0 && u < 0) u = 0;
    if (j < n - 2 && u > 1) u = 1;
    const dx = px - (ax + ex * u), dy = py - (ay + ey * u);
    const d2 = dx * dx + dy * dy;
    if (d2 < best) {
      best = d2;
      const el = Math.sqrt(el2), tx = ex / el, ty = ey / el; // tailward tangent
      PS = (j + u) / (n - 1);
      PD = dx * ty - dy * tx; // + = creature's right
      PFX = -tx;
      PFY = -ty;
    }
  }
}

/* ── plankton ── */
interface Plankton {
  x: number; y: number; vx: number; vy: number;
  ph: number; wf: number; wa: number; tw: number; op: number; g: string;
}
const PLANKTON_GLYPHS = ["-", "-", "-", "-", ".", ".", ",", "'", "*", "°"];
function makePlankton(view: View, rng: () => number) {
  const { W, H } = view, list: Plankton[] = [];
  const clusters = Math.round((W * H) / 52000);
  for (let c = 0; c < clusters; c++) {
    const cx = rng() * W, cy = rng() * H;
    const ang = rng() * 6.283, sp = 2 + 5 * rng();
    const count = 4 + ((rng() * 14) | 0), spreadX = 18 + 50 * rng(), spreadY = 10 + 34 * rng();
    const g = rng() < 0.7 ? "-" : PLANKTON_GLYPHS[(rng() * PLANKTON_GLYPHS.length) | 0];
    for (let i = 0; i < count; i++) {
      list.push({
        x: cx + (rng() + rng() - 1) * spreadX, y: cy + (rng() + rng() - 1) * spreadY,
        vx: Math.cos(ang) * sp + (rng() - 0.5) * 1.5, vy: Math.sin(ang) * sp + (rng() - 0.5) * 1.5,
        ph: rng() * 6.283, wf: 0.2 + 0.5 * rng(), wa: 3 + 6 * rng(),
        tw: 0.3 + 0.8 * rng(), op: 0.16 + 0.28 * rng(),
        g: rng() < 0.82 ? g : PLANKTON_GLYPHS[(rng() * PLANKTON_GLYPHS.length) | 0],
      });
    }
  }
  const solo = Math.round((W * H) / 30000);
  for (let i = 0; i < solo; i++) {
    list.push({
      x: rng() * W, y: rng() * H, vx: (rng() - 0.5) * 7, vy: (rng() - 0.5) * 7,
      ph: rng() * 6.283, wf: 0.2 + 0.5 * rng(), wa: 3 + 6 * rng(), tw: 0.3 + 0.8 * rng(),
      op: 0.14 + 0.2 * rng(), g: PLANKTON_GLYPHS[(rng() * PLANKTON_GLYPHS.length) | 0],
    });
  }
  return list;
}

/**
 * startAquarium draws the aquarium into canvas, sized to the window, until
 * the returned function is called. With still set, it draws one frame (a
 * few seconds in, so the sharks are in view) and doesn't animate.
 */
export function startAquarium(canvas: HTMLCanvasElement, still: boolean): () => void {
  const ctx = canvas.getContext("2d", { alpha: false });
  if (!ctx) return () => {};
  const view: View = { W: 0, H: 0, DPR: 1, cols: 0, rows: 0 };
  let cov = new Float32Array(0), fad = cov, drk = cov, cr = cov, cg = cov, cb = cov, fogC = cov, fogG = cov;
  let gridCanvas: HTMLCanvasElement = document.createElement("canvas");
  let creatures: Creature[] = [], plankton: Plankton[] = [], simT = 0;
  const colorCache = new Map<number, string>();
  function rgb(r: number, g: number, b: number) {
    const key = ((r & 0xfe) << 16) | ((g & 0xfe) << 8) | (b & 0xfe);
    let s = colorCache.get(key);
    if (!s) {
      s = `rgb(${r & 0xfe},${g & 0xfe},${b & 0xfe})`;
      colorCache.set(key, s);
    }
    return s;
  }

  function layout() {
    const W = window.innerWidth, H = window.innerHeight;
    const DPR = Math.min(2, window.devicePixelRatio || 1);
    Object.assign(view, { W, H, DPR, cols: Math.ceil(W / CELL), rows: Math.ceil(H / CELL) });
    canvas.width = Math.round(W * DPR);
    canvas.height = Math.round(H * DPR);
    const N = view.cols * view.rows;
    cov = new Float32Array(N); fad = new Float32Array(N); drk = new Float32Array(N);
    cr = new Float32Array(N); cg = new Float32Array(N); cb = new Float32Array(N);
    fogC = new Float32Array(N); fogG = new Float32Array(N);

    // radial focus fog centred on the sign-in card
    const fx = W / 2, fy = H * 0.5, R = clamp(Math.min(W, H) * 0.34, 200, 300);
    for (let y = 0; y < view.rows; y++)
      for (let x = 0; x < view.cols; x++) {
        const dx = ((x + 0.5) * CELL - fx) * 0.72, dy = (y + 0.5) * CELL - fy;
        const r = Math.sqrt(dx * dx + dy * dy);
        fogC[y * view.cols + x] = 0.42 + 0.58 * smooth(R * 0.35, R * 1.2, r);
        fogG[y * view.cols + x] = smooth(R * 0.45, R * 1.35, r);
      }

    // ghost blueprint grid, pre-rendered once
    gridCanvas = document.createElement("canvas");
    gridCanvas.width = canvas.width;
    gridCanvas.height = canvas.height;
    const g = gridCanvas.getContext("2d");
    if (!g) return;
    g.setTransform(DPR, 0, 0, DPR, 0, 0);
    g.strokeStyle = "rgba(40,40,30,0.038)";
    g.lineWidth = 1 / DPR;
    g.beginPath();
    for (let x = 0; x <= W; x += CELL) { g.moveTo(x + 0.5 / DPR, 0); g.lineTo(x + 0.5 / DPR, H); }
    for (let y = 0; y <= H; y += CELL) { g.moveTo(0, y + 0.5 / DPR); g.lineTo(W, y + 0.5 / DPR); }
    g.stroke();
    g.globalCompositeOperation = "destination-out";
    g.setTransform(DPR / 0.72, 0, 0, DPR, 0, 0);
    const grad = g.createRadialGradient(fx * 0.72, fy, 0, fx * 0.72, fy, R * 1.35);
    grad.addColorStop(0, "rgba(0,0,0,0.97)");
    grad.addColorStop(0.35, "rgba(0,0,0,0.9)");
    grad.addColorStop(1, "rgba(0,0,0,0)");
    g.fillStyle = grad;
    g.fillRect(0, 0, (W / 0.72) * 1.2, H);
  }

  function resetWorld() {
    simT = 0;
    const rng = mulberry32(7);
    creatures = [
      new Creature("hammer", 101, 0.95),
      new Creature("hammer", 202, 0.6),
      new Creature("slim", 303, 0.75),
      new Creature("hammer", 404, 0.3),
      new Creature("reef", 505, 0.45),
    ];
    // opening composition: three sharks already in the water
    creatures[0].spawn(view, { x: 0.86, y: 0.3, h: Math.PI * 0.82 });
    creatures[1].spawn(view, { x: 0.3, y: 0.92, h: -Math.PI * 0.3 });
    creatures[2].spawn(view, { x: 0.12, y: 0.26, h: -Math.PI * 0.2 });
    creatures[3].state = "wait";
    creatures[3].wait = 4.5;
    creatures[4].state = "wait";
    creatures[4].wait = 8;
    plankton = makePlankton(view, rng);
  }

  function step(dt: number) {
    simT += dt;
    for (const c of creatures) c.update(dt, simT, view);
    const { W, H } = view;
    for (const p of plankton) {
      p.x += p.vx * dt;
      p.y += p.vy * dt;
      if (p.x < -40) p.x += W + 80; else if (p.x > W + 40) p.x -= W + 80;
      if (p.y < -40) p.y += H + 80; else if (p.y > H + 40) p.y -= H + 80;
    }
  }

  function render(ctx: CanvasRenderingContext2D) {
    const { W, H, DPR, cols, rows } = view, t = simT;
    cov.fill(0);
    drk.fill(0);

    // Pass 1, "scene": rasterise skeletal creatures into the cell buffer (far → near)
    const order = creatures.filter((c) => c.state === "swim").sort((a, b) => a.z - b.z);
    for (const c of order) {
      const b = c.bbox, lut = c.k.lut, shape = c.k.shape;
      const x0 = Math.max(0, Math.floor(b.x0 / CELL)), x1 = Math.min(cols - 1, Math.floor(b.x1 / CELL));
      const y0 = Math.max(0, Math.floor(b.y0 / CELL)), y1 = Math.min(rows - 1, Math.floor(b.y1 / CELL));
      if (x0 > x1 || y0 > y1) continue;
      const lim = c.k.margin * c.L * 1.05;
      const alphaZ = 0.55 + 0.45 * c.z;
      const contrast = 0.5 + 0.5 * c.z;
      const soft = CELL * 1.1;
      for (let y = y0; y <= y1; y++) {
        const py = (y + 0.5) * CELL;
        for (let x = x0; x <= x1; x++) {
          const px = (x + 0.5) * CELL;
          project(c, px, py);
          if (PD > lim || PD < -lim || PS < -0.12 || PS > 1.25) continue;
          const sdf = shape(c, PS, PD, PFX, PFY);
          const a = clamp(0.62 - sdf / soft, 0, 1);
          if (a <= 0) continue;
          let dark = OUT.dark;
          dark += (tnoise(x, y, t * 3.2 + c.z * 9) - 0.5) * 0.2; // living shimmer
          dark = 0.14 + (clamp(dark, 0, 1) - 0.14) * contrast; // depth haze
          dark = clamp(dark, 0, 1);
          const li = ((dark * 255) | 0) * 3;
          const i = y * cols + x, oc = cov[i], nc = a + oc * (1 - a);
          const w = a / nc;
          cr[i] = oc ? lerp(cr[i], lut[li], w) : lut[li];
          cg[i] = oc ? lerp(cg[i], lut[li + 1], w) : lut[li + 1];
          cb[i] = oc ? lerp(cb[i], lut[li + 2], w) : lut[li + 2];
          drk[i] = oc ? lerp(drk[i], dark, w) : dark;
          fad[i] = oc ? lerp(fad[i], alphaZ, w) : alphaZ;
          cov[i] = nc;
        }
      }
    }

    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    ctx.fillStyle = BG_STR;
    ctx.fillRect(0, 0, W, H);
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.drawImage(gridCanvas, 0, 0);
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);

    // Pass 3 (drawn beneath tiles so creatures occlude): digital plankton
    ctx.font = `10px ${MONO}`;
    for (const p of plankton) {
      const wx = p.x + Math.sin(t * p.wf + p.ph) * p.wa, wy = p.y + Math.cos(t * p.wf * 0.8 + p.ph) * p.wa * 0.6;
      const cx = Math.floor(wx / CELL), cy = Math.floor(wy / CELL);
      if (cx < 0 || cy < 0 || cx >= cols || cy >= rows) continue;
      const i = cy * cols + cx;
      if (cov[i] > 0.12) continue;
      const op = p.op * fogG[i] * (0.55 + 0.45 * Math.sin(t * p.tw + p.ph * 2));
      if (op < 0.02) continue;
      ctx.fillStyle = `rgba(70,70,66,${op.toFixed(3)})`;
      const X = cx * CELL, Y = cy * CELL;
      if (p.g === "-") ctx.fillRect(X + 3.5, Y + 6, 6, 1);
      else if (p.g === ".") ctx.fillRect(X + 5.5, Y + 7.5, 1.6, 1.6);
      else {
        ctx.textAlign = "center";
        ctx.textBaseline = "middle";
        ctx.fillText(p.g, X + CELL / 2, Y + CELL / 2 + 0.5);
      }
    }

    // Pass 2: ASCII mosaic, tile fill + glyph per cell
    ctx.font = `500 ${Math.round(CELL * 0.74)}px ${MONO}`;
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    const accentEpoch = Math.floor(t * 0.6);
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        const i = y * cols + x, c0 = cov[i];
        if (c0 < 0.08) continue;
        const vis = fad[i] * fogC[i]; // depth fade × focus fog
        const X = x * CELL, Y = y * CELL;
        let r = cr[i], g = cg[i], b = cb[i];
        if (c0 < 0.42) {
          // diffuse silhouette edge: a lone speck, no tile
          const k = clamp(c0 * 2.2 * vis, 0, 1);
          ctx.fillStyle = rgb((BG[0] + (r - 60 - BG[0]) * k) | 0, (BG[1] + (g - 60 - BG[1]) * k) | 0, (BG[2] + (b - 60 - BG[2]) * k) | 0);
          ctx.fillText(HALO[(hash(x, y, 3) * HALO.length) | 0], X + CELL / 2, Y + CELL / 2);
          continue;
        }
        const alpha = vis;
        // chromatic micro-accents: iridescence on wet scales
        const h = hash(x, y, accentEpoch + ((hash(x, y, 9) * 7) | 0));
        if (h < 0.05) {
          const a = ACCENTS[Math.min(2, (h * 60) | 0)], m = 0.55;
          r = lerp(r, a[0], m);
          g = lerp(g, a[1], m);
          b = lerp(b, a[2], m);
        }
        const k = (0.35 + 0.65 * smooth(0.42, 0.85, c0)) * (0.25 + 0.75 * alpha);
        const fr = BG[0] + (r - BG[0]) * k, fg = BG[1] + (g - BG[1]) * k, fb = BG[2] + (b - BG[2]) * k;
        // tile, inset 1px so the porcelain shows through as a keycap seam
        ctx.fillStyle = rgb(fr | 0, fg | 0, fb | 0);
        ctx.fillRect(X + 1, Y + 1, CELL - 1, CELL - 1);
        // glyph from the density ramp
        const lum = (0.3 * fr + 0.59 * fg + 0.11 * fb) / 255;
        const dd = clamp(drk[i] * (0.6 + 0.4 * alpha), 0, 0.999);
        const ch = RAMP[(dd * RAMP.length) | 0];
        if (lum < 0.5) ctx.fillStyle = rgb((fr + (255 - fr) * 0.42) | 0, (fg + (255 - fg) * 0.42) | 0, (fb + (255 - fb) * 0.42) | 0);
        else ctx.fillStyle = rgb((fr * 0.42 + 8) | 0, (fg * 0.42 + 8) | 0, (fb * 0.42 + 8) | 0);
        ctx.fillText(ch, X + CELL / 2 + 0.5, Y + CELL / 2 + 1);
      }
    }
  }

  // A still frame: a few seconds in, so the opening sharks have moved into view.
  function drawStill() {
    resetWorld();
    while (simT < 6) step(SIM_DT);
    render(ctx!);
  }

  let acc = 0, last = 0, raf = 0, stopped = false;
  function frame(now: number) {
    if (stopped) return;
    const dt = Math.min(0.1, (now - (last || now)) / 1000);
    last = now;
    acc += dt;
    while (acc >= SIM_DT) {
      step(SIM_DT);
      acc -= SIM_DT;
    }
    render(ctx!);
    raf = requestAnimationFrame(frame);
  }

  let resizeTimer = 0;
  const onResize = () => {
    clearTimeout(resizeTimer);
    resizeTimer = window.setTimeout(() => {
      layout();
      if (still) drawStill();
      else resetWorld();
    }, 120);
  };
  window.addEventListener("resize", onResize);

  layout();
  if (still) drawStill();
  else {
    resetWorld();
    raf = requestAnimationFrame(frame);
  }
  return () => {
    stopped = true;
    cancelAnimationFrame(raf);
    clearTimeout(resizeTimer);
    window.removeEventListener("resize", onResize);
  };
}
