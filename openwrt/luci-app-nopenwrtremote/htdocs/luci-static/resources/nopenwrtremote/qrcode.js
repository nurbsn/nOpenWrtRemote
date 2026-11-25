/* Self-contained offline QR Code SVG generator (Byte mode, ECC Level L, Versions 1..10) for LuCI JS */
'use strict';

window.NortQrCode = (function () {
  var VERSIONS = [
    null,
    { size: 21, totalCodewords: 26, dataCodewords: 19, ecPerBlock: 7, blocks: 1, align: [] },
    { size: 25, totalCodewords: 44, dataCodewords: 34, ecPerBlock: 10, blocks: 1, align: [6, 18] },
    { size: 29, totalCodewords: 70, dataCodewords: 55, ecPerBlock: 15, blocks: 1, align: [6, 22] },
    { size: 33, totalCodewords: 100, dataCodewords: 80, ecPerBlock: 20, blocks: 1, align: [6, 26] },
    { size: 37, totalCodewords: 134, dataCodewords: 108, ecPerBlock: 26, blocks: 1, align: [6, 30] },
    { size: 41, totalCodewords: 172, dataCodewords: 136, ecPerBlock: 18, blocks: 2, align: [6, 34] },
    { size: 45, totalCodewords: 196, dataCodewords: 156, ecPerBlock: 20, blocks: 2, align: [6, 22, 38] },
    { size: 49, totalCodewords: 242, dataCodewords: 194, ecPerBlock: 24, blocks: 2, align: [6, 24, 42] },
    { size: 53, totalCodewords: 292, dataCodewords: 232, ecPerBlock: 30, blocks: 2, align: [6, 26, 46] },
    { size: 57, totalCodewords: 346, dataCodewords: 274, ecPerBlock: 18, blocks: 4, align: [6, 28, 50] }
  ];

  var GF_EXP = new Uint8Array(512);
  var GF_LOG = new Uint8Array(256);
  (function initGF() {
    var x = 1;
    for (var i = 0; i < 255; i++) {
      GF_EXP[i] = x;
      GF_LOG[x] = i;
      x <<= 1;
      if (x & 0x100) x ^= 0x11d;
    }
    for (var j = 255; j < 512; j++) GF_EXP[j] = GF_EXP[j - 255];
  })();

  function gfMul(a, b) {
    if (a === 0 || b === 0) return 0;
    return GF_EXP[GF_LOG[a] + GF_LOG[b]];
  }

  function rsGenerator(degree) {
    var poly = [1];
    for (var i = 0; i < degree; i++) {
      var next = new Array(poly.length + 1).fill(0);
      var factor = GF_EXP[i];
      for (var j = 0; j < poly.length; j++) {
        next[j] ^= poly[j];
        next[j + 1] ^= gfMul(poly[j], factor);
      }
      poly = next;
    }
    return poly;
  }

  function rsRemainder(data, ecLen) {
    var gen = rsGenerator(ecLen);
    var res = new Array(ecLen).fill(0);
    for (var i = 0; i < data.length; i++) {
      var factor = data[i] ^ res.shift();
      res.push(0);
      if (factor !== 0) {
        for (var j = 0; j < ecLen; j++) {
          res[j] ^= gfMul(gen[j + 1], factor);
        }
      }
    }
    return res;
  }

  function utf8Bytes(str) {
    if (typeof TextEncoder !== 'undefined') return Array.from(new TextEncoder().encode(str));
    var out = [];
    for (var i = 0; i < str.length; i++) {
      var c = str.charCodeAt(i);
      if (c < 128) out.push(c);
      else out.push(63);
    }
    return out;
  }

  function pushBits(bits, val, len) {
    for (var i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  }

  function chooseVersion(byteLen) {
    for (var v = 1; v < VERSIONS.length; v++) {
      var capBits = VERSIONS[v].dataCodewords * 8;
      var needed = 4 + (v >= 10 ? 16 : 8) + byteLen * 8;
      if (needed <= capBits) return v;
    }
    throw new Error('QR payload too long: ' + byteLen + ' bytes');
  }

  function buildCodewords(bytes, version) {
    var spec = VERSIONS[version];
    var bits = [];
    pushBits(bits, 0x4, 4); // Byte mode
    pushBits(bits, bytes.length, version >= 10 ? 16 : 8);
    for (var i = 0; i < bytes.length; i++) pushBits(bits, bytes[i], 8);

    var maxBits = spec.dataCodewords * 8;
    var term = Math.min(4, maxBits - bits.length);
    for (var t = 0; t < term; t++) bits.push(0);
    while (bits.length % 8 !== 0) bits.push(0);

    var data = [];
    for (var b = 0; b < bits.length; b += 8) {
      var byteVal = 0;
      for (var k = 0; k < 8; k++) byteVal = (byteVal << 1) | bits[b + k];
      data.push(byteVal);
    }
    var padIdx = 0;
    while (data.length < spec.dataCodewords) {
      data.push(padIdx % 2 === 0 ? 0xec : 0x11);
      padIdx++;
    }

    var blocks = [];
    var ecBlocks = [];
    var blockSize = Math.floor(spec.dataCodewords / spec.blocks);
    var extra = spec.dataCodewords % spec.blocks;
    var offset = 0;
    for (var bi = 0; bi < spec.blocks; bi++) {
      var len = blockSize + (bi >= spec.blocks - extra ? 1 : 0);
      var slice = data.slice(offset, offset + len);
      offset += len;
      blocks.push(slice);
      ecBlocks.push(rsRemainder(slice, spec.ecPerBlock));
    }

    var result = [];
    var maxDataLen = blockSize + (extra > 0 ? 1 : 0);
    for (var r = 0; r < maxDataLen; r++) {
      for (var bl = 0; bl < blocks.length; bl++) {
        if (r < blocks[bl].length) result.push(blocks[bl][r]);
      }
    }
    for (var e = 0; e < spec.ecPerBlock; e++) {
      for (var ebl = 0; ebl < ecBlocks.length; ebl++) {
        result.push(ecBlocks[ebl][e]);
      }
    }
    return result;
  }

  function makeMatrix(version) {
    var size = VERSIONS[version].size;
    var grid = Array.from({ length: size }, function () { return new Int8Array(size).fill(-1); });
    var isFunc = Array.from({ length: size }, function () { return new Uint8Array(size); });

    function setFunc(r, c, val) {
      if (r < 0 || c < 0 || r >= size || c >= size) return;
      grid[r][c] = val ? 1 : 0;
      isFunc[r][c] = 1;
    }

    function drawFinder(r0, c0) {
      for (var dr = -1; dr <= 7; dr++) {
        for (var dc = -1; dc <= 7; dc++) {
          var r = r0 + dr, c = c0 + dc;
          if (r < 0 || c < 0 || r >= size || c >= size) continue;
          var dark = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6 &&
            (dr === 0 || dr === 6 || dc === 0 || dc === 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
          setFunc(r, c, dark);
        }
      }
    }

    drawFinder(0, 0);
    drawFinder(0, size - 7);
    drawFinder(size - 7, 0);

    for (var i = 8; i < size - 8; i++) {
      setFunc(6, i, i % 2 === 0);
      setFunc(i, 6, i % 2 === 0);
    }
    setFunc(size - 8, 8, 1);

    var align = VERSIONS[version].align;
    for (var ai = 0; ai < align.length; ai++) {
      for (var aj = 0; aj < align.length; aj++) {
        var ar = align[ai], ac = align[aj];
        if ((ar === 6 && ac === 6) || (ar === 6 && ac === size - 7) || (ar === size - 7 && ac === 6)) continue;
        for (var dr = -2; dr <= 2; dr++) {
          for (var dc = -2; dc <= 2; dc++) {
            setFunc(ar + dr, ac + dc, Math.max(Math.abs(dr), Math.abs(dc)) !== 1);
          }
        }
      }
    }

    for (var f = 0; f < 9; f++) {
      if (f !== 6) {
        isFunc[8][f] = 1;
        isFunc[f][8] = 1;
      }
      if (f < 8) {
        isFunc[8][size - 1 - f] = 1;
        isFunc[size - 1 - f][8] = 1;
      }
    }
    if (version >= 7) {
      for (var a = 0; a < 6; a++) {
        for (var b = 0; b < 3; b++) {
          isFunc[a][size - 11 + b] = 1;
          isFunc[size - 11 + b][a] = 1;
        }
      }
    }

    return { size: size, grid: grid, isFunc: isFunc };
  }

  function applyFormat(matrix, version, mask) {
    var size = matrix.size;
    // ECC L = 01
    var data = (1 << 3) | mask;
    var rem = data;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var bits = ((data << 10) | rem) ^ 0x5412;

    for (var j = 0; j < 6; j++) matrix.grid[8][j] = (bits >>> j) & 1;
    matrix.grid[8][7] = (bits >>> 6) & 1;
    matrix.grid[8][8] = (bits >>> 7) & 1;
    matrix.grid[7][8] = (bits >>> 8) & 1;
    for (var k = 9; k < 15; k++) matrix.grid[14 - k][8] = (bits >>> k) & 1;

    for (var m = 0; m < 8; m++) matrix.grid[size - 1 - m][8] = (bits >>> m) & 1;
    for (var n = 8; n < 15; n++) matrix.grid[8][size - 15 + n] = (bits >>> n) & 1;

    if (version >= 7) {
      var vrem = version;
      for (var vi = 0; vi < 12; vi++) vrem = (vrem << 1) ^ ((vrem >>> 11) * 0x1f25);
      var vbits = (version << 12) | vrem;
      for (var va = 0; va < 18; va++) {
        var bit = (vbits >>> va) & 1;
        var r = Math.floor(va / 3), c = size - 11 + (va % 3);
        matrix.grid[r][c] = bit;
        matrix.grid[c][r] = bit;
      }
    }
  }

  function renderSvg(text, pixelSize) {
    pixelSize = pixelSize || 240;
    var bytes = utf8Bytes(text);
    var version = chooseVersion(bytes.length);
    var codewords = buildCodewords(bytes, version);
    var matrix = makeMatrix(version);
    var size = matrix.size;

    var bitIdx = 0;
    var totalBits = codewords.length * 8;
    var dir = -1;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vert = 0; vert < size; vert++) {
        var r = dir === -1 ? size - 1 - vert : vert;
        for (var dx = 0; dx < 2; dx++) {
          var c = right - dx;
          if (matrix.isFunc[r][c]) continue;
          var dark = false;
          if (bitIdx < totalBits) {
            dark = ((codewords[bitIdx >>> 3] >>> (7 - (bitIdx & 7))) & 1) === 1;
            bitIdx++;
          }
          // Mask 0: (r + c) % 2 === 0
          if ((r + c) % 2 === 0) dark = !dark;
          matrix.grid[r][c] = dark ? 1 : 0;
        }
      }
      dir = -dir;
    }

    applyFormat(matrix, version, 0);

    var quiet = 4;
    var dim = size + quiet * 2;
    var paths = [];
    for (var y = 0; y < size; y++) {
      for (var x = 0; x < size; x++) {
        if (matrix.grid[y][x] === 1) {
          paths.push('M' + (x + quiet) + ',' + (y + quiet) + 'h1v1h-1z');
        }
      }
    }
    return '<svg xmlns="http://www.w3.org/2000/svg" width="' + pixelSize + '" height="' + pixelSize +
      '" viewBox="0 0 ' + dim + ' ' + dim + '" shape-rendering="crispEdges">' +
      '<rect width="100%" height="100%" fill="#ffffff"/>' +
      '<path d="' + paths.join('') + '" fill="#000000"/>' +
      '</svg>';
  }

  return { renderSvg: renderSvg };
})();
