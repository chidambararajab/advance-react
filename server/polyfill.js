// Polyfill File for Node.js environment
const { File } = require("buffer");
globalThis.File = File;

