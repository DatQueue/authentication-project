exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 35:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getStorageToken = exports.getOptionsToken = void 0;
__exportStar(__webpack_require__(36), exports);
__exportStar(__webpack_require__(37), exports);
__exportStar(__webpack_require__(38), exports);
__exportStar(__webpack_require__(42), exports);
__exportStar(__webpack_require__(43), exports);
__exportStar(__webpack_require__(48), exports);
var throttler_providers_1 = __webpack_require__(40);
Object.defineProperty(exports, "getOptionsToken", ({ enumerable: true, get: function () { return throttler_providers_1.getOptionsToken; } }));
Object.defineProperty(exports, "getStorageToken", ({ enumerable: true, get: function () { return throttler_providers_1.getStorageToken; } }));
__exportStar(__webpack_require__(41), exports);
//# sourceMappingURL=index.js.map

/***/ }),

/***/ 36:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
//# sourceMappingURL=throttler-module-options.interface.js.map

/***/ }),

/***/ 37:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ThrottlerStorage = void 0;
exports.ThrottlerStorage = Symbol('ThrottlerStorage');
//# sourceMappingURL=throttler-storage.interface.js.map

/***/ }),

/***/ 39:
/***/ ((__unused_webpack_module, exports) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.THROTTLER_SKIP = exports.THROTTLER_OPTIONS = exports.THROTTLER_TTL = exports.THROTTLER_LIMIT = void 0;
exports.THROTTLER_LIMIT = 'THROTTLER:LIMIT';
exports.THROTTLER_TTL = 'THROTTLER:TTL';
exports.THROTTLER_OPTIONS = 'THROTTLER:MODULE_OPTIONS';
exports.THROTTLER_SKIP = 'THROTTLER:SKIP';
//# sourceMappingURL=throttler.constants.js.map

/***/ }),

/***/ 38:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.InjectThrottlerStorage = exports.InjectThrottlerOptions = exports.SkipThrottle = exports.Throttle = void 0;
const common_1 = __webpack_require__(6);
const throttler_constants_1 = __webpack_require__(39);
const throttler_providers_1 = __webpack_require__(40);
function setThrottlerMetadata(target, limit, ttl) {
    Reflect.defineMetadata(throttler_constants_1.THROTTLER_TTL, ttl, target);
    Reflect.defineMetadata(throttler_constants_1.THROTTLER_LIMIT, limit, target);
}
const Throttle = (limit = 20, ttl = 60) => {
    return (target, propertyKey, descriptor) => {
        if (descriptor) {
            setThrottlerMetadata(descriptor.value, limit, ttl);
            return descriptor;
        }
        setThrottlerMetadata(target, limit, ttl);
        return target;
    };
};
exports.Throttle = Throttle;
const SkipThrottle = (skip = true) => {
    return (target, propertyKey, descriptor) => {
        if (descriptor) {
            Reflect.defineMetadata(throttler_constants_1.THROTTLER_SKIP, skip, descriptor.value);
            return descriptor;
        }
        Reflect.defineMetadata(throttler_constants_1.THROTTLER_SKIP, skip, target);
        return target;
    };
};
exports.SkipThrottle = SkipThrottle;
const InjectThrottlerOptions = () => (0, common_1.Inject)((0, throttler_providers_1.getOptionsToken)());
exports.InjectThrottlerOptions = InjectThrottlerOptions;
const InjectThrottlerStorage = () => (0, common_1.Inject)((0, throttler_providers_1.getStorageToken)());
exports.InjectThrottlerStorage = InjectThrottlerStorage;
//# sourceMappingURL=throttler.decorator.js.map

/***/ }),

/***/ 42:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ThrottlerException = exports.throttlerMessage = void 0;
const common_1 = __webpack_require__(6);
exports.throttlerMessage = 'ThrottlerException: Too Many Requests';
class ThrottlerException extends common_1.HttpException {
    constructor(message) {
        super(`${message || exports.throttlerMessage}`, common_1.HttpStatus.TOO_MANY_REQUESTS);
    }
}
exports.ThrottlerException = ThrottlerException;
//# sourceMappingURL=throttler.exception.js.map

/***/ }),

/***/ 43:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var __param = (this && this.__param) || function (paramIndex, decorator) {
    return function (target, key) { decorator(target, key, paramIndex); }
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ThrottlerGuard = void 0;
const common_1 = __webpack_require__(6);
const core_1 = __webpack_require__(4);
const md5 = __webpack_require__(44);
const throttler_storage_interface_1 = __webpack_require__(37);
const throttler_constants_1 = __webpack_require__(39);
const throttler_decorator_1 = __webpack_require__(38);
const throttler_exception_1 = __webpack_require__(42);
let ThrottlerGuard = class ThrottlerGuard {
    constructor(options, storageService, reflector) {
        this.options = options;
        this.storageService = storageService;
        this.reflector = reflector;
        this.headerPrefix = 'X-RateLimit';
        this.errorMessage = throttler_exception_1.throttlerMessage;
    }
    async canActivate(context) {
        var _a, _b;
        const handler = context.getHandler();
        const classRef = context.getClass();
        if (this.reflector.getAllAndOverride(throttler_constants_1.THROTTLER_SKIP, [handler, classRef]) ||
            ((_b = (_a = this.options).skipIf) === null || _b === void 0 ? void 0 : _b.call(_a, context))) {
            return true;
        }
        const routeOrClassLimit = this.reflector.getAllAndOverride(throttler_constants_1.THROTTLER_LIMIT, [
            handler,
            classRef,
        ]);
        const routeOrClassTtl = this.reflector.getAllAndOverride(throttler_constants_1.THROTTLER_TTL, [
            handler,
            classRef,
        ]);
        const limit = routeOrClassLimit || this.options.limit;
        const ttl = routeOrClassTtl || this.options.ttl;
        return this.handleRequest(context, limit, ttl);
    }
    async handleRequest(context, limit, ttl) {
        const { req, res } = this.getRequestResponse(context);
        if (Array.isArray(this.options.ignoreUserAgents)) {
            for (const pattern of this.options.ignoreUserAgents) {
                if (pattern.test(req.headers['user-agent'])) {
                    return true;
                }
            }
        }
        const tracker = this.getTracker(req);
        const key = this.generateKey(context, tracker);
        const { totalHits, timeToExpire } = await this.storageService.increment(key, ttl);
        if (totalHits > limit) {
            res.header('Retry-After', timeToExpire);
            this.throwThrottlingException(context);
        }
        res.header(`${this.headerPrefix}-Limit`, limit);
        res.header(`${this.headerPrefix}-Remaining`, Math.max(0, limit - totalHits));
        res.header(`${this.headerPrefix}-Reset`, timeToExpire);
        return true;
    }
    getTracker(req) {
        return req.ip;
    }
    getRequestResponse(context) {
        const http = context.switchToHttp();
        return { req: http.getRequest(), res: http.getResponse() };
    }
    generateKey(context, suffix) {
        const prefix = `${context.getClass().name}-${context.getHandler().name}`;
        return md5(`${prefix}-${suffix}`);
    }
    throwThrottlingException(context) {
        throw new throttler_exception_1.ThrottlerException(this.errorMessage);
    }
};
ThrottlerGuard = __decorate([
    (0, common_1.Injectable)(),
    __param(0, (0, throttler_decorator_1.InjectThrottlerOptions)()),
    __param(1, (0, throttler_decorator_1.InjectThrottlerStorage)()),
    __metadata("design:paramtypes", [Object, Object, core_1.Reflector])
], ThrottlerGuard);
exports.ThrottlerGuard = ThrottlerGuard;
//# sourceMappingURL=throttler.guard.js.map

/***/ }),

/***/ 48:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var ThrottlerModule_1;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ThrottlerModule = void 0;
const common_1 = __webpack_require__(6);
const throttler_constants_1 = __webpack_require__(39);
const throttler_providers_1 = __webpack_require__(40);
let ThrottlerModule = ThrottlerModule_1 = class ThrottlerModule {
    static forRoot(options = {}) {
        const providers = [...(0, throttler_providers_1.createThrottlerProviders)(options), throttler_providers_1.ThrottlerStorageProvider];
        return {
            module: ThrottlerModule_1,
            providers,
            exports: providers,
        };
    }
    static forRootAsync(options) {
        const providers = [...this.createAsyncProviders(options), throttler_providers_1.ThrottlerStorageProvider];
        return {
            module: ThrottlerModule_1,
            imports: options.imports || [],
            providers,
            exports: providers,
        };
    }
    static createAsyncProviders(options) {
        if (options.useExisting || options.useFactory) {
            return [this.createAsyncOptionsProvider(options)];
        }
        return [
            this.createAsyncOptionsProvider(options),
            {
                provide: options.useClass,
                useClass: options.useClass,
            },
        ];
    }
    static createAsyncOptionsProvider(options) {
        if (options.useFactory) {
            return {
                provide: throttler_constants_1.THROTTLER_OPTIONS,
                useFactory: options.useFactory,
                inject: options.inject || [],
            };
        }
        return {
            provide: throttler_constants_1.THROTTLER_OPTIONS,
            useFactory: async (optionsFactory) => await optionsFactory.createThrottlerOptions(),
            inject: [options.useExisting || options.useClass],
        };
    }
};
ThrottlerModule = ThrottlerModule_1 = __decorate([
    (0, common_1.Global)(),
    (0, common_1.Module)({})
], ThrottlerModule);
exports.ThrottlerModule = ThrottlerModule;
//# sourceMappingURL=throttler.module.js.map

/***/ }),

/***/ 40:
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {

"use strict";

Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getStorageToken = exports.getOptionsToken = exports.ThrottlerStorageProvider = exports.createThrottlerProviders = void 0;
const throttler_storage_interface_1 = __webpack_require__(37);
const throttler_constants_1 = __webpack_require__(39);
const throttler_service_1 = __webpack_require__(41);
function createThrottlerProviders(options) {
    return [
        {
            provide: throttler_constants_1.THROTTLER_OPTIONS,
            useValue: options,
        },
    ];
}
exports.createThrottlerProviders = createThrottlerProviders;
exports.ThrottlerStorageProvider = {
    provide: throttler_storage_interface_1.ThrottlerStorage,
    useFactory: (options) => {
        return options.storage ? options.storage : new throttler_service_1.ThrottlerStorageService();
    },
    inject: [throttler_constants_1.THROTTLER_OPTIONS],
};
const getOptionsToken = () => throttler_constants_1.THROTTLER_OPTIONS;
exports.getOptionsToken = getOptionsToken;
const getStorageToken = () => throttler_storage_interface_1.ThrottlerStorage;
exports.getStorageToken = getStorageToken;
//# sourceMappingURL=throttler.providers.js.map

/***/ }),

/***/ 41:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ThrottlerStorageService = void 0;
const common_1 = __webpack_require__(6);
let ThrottlerStorageService = class ThrottlerStorageService {
    constructor() {
        this._storage = {};
        this.timeoutIds = [];
    }
    get storage() {
        return this._storage;
    }
    getExpirationTime(key) {
        return Math.floor((this.storage[key].expiresAt - Date.now()) / 1000);
    }
    setExpirationTime(key, ttlMilliseconds) {
        const timeoutId = setTimeout(() => {
            this.storage[key].totalHits--;
            clearTimeout(timeoutId);
            this.timeoutIds = this.timeoutIds.filter((id) => id != timeoutId);
        }, ttlMilliseconds);
        this.timeoutIds.push(timeoutId);
    }
    async increment(key, ttl) {
        const ttlMilliseconds = ttl * 1000;
        if (!this.storage[key]) {
            this.storage[key] = { totalHits: 0, expiresAt: Date.now() + ttlMilliseconds };
        }
        let timeToExpire = this.getExpirationTime(key);
        if (timeToExpire <= 0) {
            this.storage[key].expiresAt = Date.now() + ttlMilliseconds;
            timeToExpire = this.getExpirationTime(key);
        }
        this.storage[key].totalHits++;
        this.setExpirationTime(key, ttlMilliseconds);
        return {
            totalHits: this.storage[key].totalHits,
            timeToExpire,
        };
    }
    onApplicationShutdown() {
        this.timeoutIds.forEach(clearTimeout);
    }
};
ThrottlerStorageService = __decorate([
    (0, common_1.Injectable)()
], ThrottlerStorageService);
exports.ThrottlerStorageService = ThrottlerStorageService;
//# sourceMappingURL=throttler.service.js.map

/***/ }),

/***/ 46:
/***/ ((module) => {

var charenc = {
  // UTF-8 encoding
  utf8: {
    // Convert a string to a byte array
    stringToBytes: function(str) {
      return charenc.bin.stringToBytes(unescape(encodeURIComponent(str)));
    },

    // Convert a byte array to a string
    bytesToString: function(bytes) {
      return decodeURIComponent(escape(charenc.bin.bytesToString(bytes)));
    }
  },

  // Binary encoding
  bin: {
    // Convert a string to a byte array
    stringToBytes: function(str) {
      for (var bytes = [], i = 0; i < str.length; i++)
        bytes.push(str.charCodeAt(i) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a string
    bytesToString: function(bytes) {
      for (var str = [], i = 0; i < bytes.length; i++)
        str.push(String.fromCharCode(bytes[i]));
      return str.join('');
    }
  }
};

module.exports = charenc;


/***/ }),

/***/ 45:
/***/ ((module) => {

(function() {
  var base64map
      = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',

  crypt = {
    // Bit-wise rotation left
    rotl: function(n, b) {
      return (n << b) | (n >>> (32 - b));
    },

    // Bit-wise rotation right
    rotr: function(n, b) {
      return (n << (32 - b)) | (n >>> b);
    },

    // Swap big-endian to little-endian and vice versa
    endian: function(n) {
      // If number given, swap endian
      if (n.constructor == Number) {
        return crypt.rotl(n, 8) & 0x00FF00FF | crypt.rotl(n, 24) & 0xFF00FF00;
      }

      // Else, assume array and swap all items
      for (var i = 0; i < n.length; i++)
        n[i] = crypt.endian(n[i]);
      return n;
    },

    // Generate an array of any length of random bytes
    randomBytes: function(n) {
      for (var bytes = []; n > 0; n--)
        bytes.push(Math.floor(Math.random() * 256));
      return bytes;
    },

    // Convert a byte array to big-endian 32-bit words
    bytesToWords: function(bytes) {
      for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
        words[b >>> 5] |= bytes[i] << (24 - b % 32);
      return words;
    },

    // Convert big-endian 32-bit words to a byte array
    wordsToBytes: function(words) {
      for (var bytes = [], b = 0; b < words.length * 32; b += 8)
        bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
      return bytes;
    },

    // Convert a byte array to a hex string
    bytesToHex: function(bytes) {
      for (var hex = [], i = 0; i < bytes.length; i++) {
        hex.push((bytes[i] >>> 4).toString(16));
        hex.push((bytes[i] & 0xF).toString(16));
      }
      return hex.join('');
    },

    // Convert a hex string to a byte array
    hexToBytes: function(hex) {
      for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
      return bytes;
    },

    // Convert a byte array to a base-64 string
    bytesToBase64: function(bytes) {
      for (var base64 = [], i = 0; i < bytes.length; i += 3) {
        var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        for (var j = 0; j < 4; j++)
          if (i * 8 + j * 6 <= bytes.length * 8)
            base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
          else
            base64.push('=');
      }
      return base64.join('');
    },

    // Convert a base-64 string to a byte array
    base64ToBytes: function(base64) {
      // Remove non-base-64 characters
      base64 = base64.replace(/[^A-Z0-9+\/]/ig, '');

      for (var bytes = [], i = 0, imod4 = 0; i < base64.length;
          imod4 = ++i % 4) {
        if (imod4 == 0) continue;
        bytes.push(((base64map.indexOf(base64.charAt(i - 1))
            & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2))
            | (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
      }
      return bytes;
    }
  };

  module.exports = crypt;
})();


/***/ }),

/***/ 47:
/***/ ((module) => {

/*!
 * Determine if an object is a Buffer
 *
 * @author   Feross Aboukhadijeh <https://feross.org>
 * @license  MIT
 */

// The _isBuffer check is for Safari 5-7 support, because it's missing
// Object.prototype.constructor. Remove this eventually
module.exports = function (obj) {
  return obj != null && (isBuffer(obj) || isSlowBuffer(obj) || !!obj._isBuffer)
}

function isBuffer (obj) {
  return !!obj.constructor && typeof obj.constructor.isBuffer === 'function' && obj.constructor.isBuffer(obj)
}

// For Node v0.10 support. Remove this eventually.
function isSlowBuffer (obj) {
  return typeof obj.readFloatLE === 'function' && typeof obj.slice === 'function' && isBuffer(obj.slice(0, 0))
}


/***/ }),

/***/ 44:
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

(function(){
  var crypt = __webpack_require__(45),
      utf8 = (__webpack_require__(46).utf8),
      isBuffer = __webpack_require__(47),
      bin = (__webpack_require__(46).bin),

  // The core
  md5 = function (message, options) {
    // Convert to byte array
    if (message.constructor == String)
      if (options && options.encoding === 'binary')
        message = bin.stringToBytes(message);
      else
        message = utf8.stringToBytes(message);
    else if (isBuffer(message))
      message = Array.prototype.slice.call(message, 0);
    else if (!Array.isArray(message) && message.constructor !== Uint8Array)
      message = message.toString();
    // else, assume byte array already

    var m = crypt.bytesToWords(message),
        l = message.length * 8,
        a =  1732584193,
        b = -271733879,
        c = -1732584194,
        d =  271733878;

    // Swap endian
    for (var i = 0; i < m.length; i++) {
      m[i] = ((m[i] <<  8) | (m[i] >>> 24)) & 0x00FF00FF |
             ((m[i] << 24) | (m[i] >>>  8)) & 0xFF00FF00;
    }

    // Padding
    m[l >>> 5] |= 0x80 << (l % 32);
    m[(((l + 64) >>> 9) << 4) + 14] = l;

    // Method shortcuts
    var FF = md5._ff,
        GG = md5._gg,
        HH = md5._hh,
        II = md5._ii;

    for (var i = 0; i < m.length; i += 16) {

      var aa = a,
          bb = b,
          cc = c,
          dd = d;

      a = FF(a, b, c, d, m[i+ 0],  7, -680876936);
      d = FF(d, a, b, c, m[i+ 1], 12, -389564586);
      c = FF(c, d, a, b, m[i+ 2], 17,  606105819);
      b = FF(b, c, d, a, m[i+ 3], 22, -1044525330);
      a = FF(a, b, c, d, m[i+ 4],  7, -176418897);
      d = FF(d, a, b, c, m[i+ 5], 12,  1200080426);
      c = FF(c, d, a, b, m[i+ 6], 17, -1473231341);
      b = FF(b, c, d, a, m[i+ 7], 22, -45705983);
      a = FF(a, b, c, d, m[i+ 8],  7,  1770035416);
      d = FF(d, a, b, c, m[i+ 9], 12, -1958414417);
      c = FF(c, d, a, b, m[i+10], 17, -42063);
      b = FF(b, c, d, a, m[i+11], 22, -1990404162);
      a = FF(a, b, c, d, m[i+12],  7,  1804603682);
      d = FF(d, a, b, c, m[i+13], 12, -40341101);
      c = FF(c, d, a, b, m[i+14], 17, -1502002290);
      b = FF(b, c, d, a, m[i+15], 22,  1236535329);

      a = GG(a, b, c, d, m[i+ 1],  5, -165796510);
      d = GG(d, a, b, c, m[i+ 6],  9, -1069501632);
      c = GG(c, d, a, b, m[i+11], 14,  643717713);
      b = GG(b, c, d, a, m[i+ 0], 20, -373897302);
      a = GG(a, b, c, d, m[i+ 5],  5, -701558691);
      d = GG(d, a, b, c, m[i+10],  9,  38016083);
      c = GG(c, d, a, b, m[i+15], 14, -660478335);
      b = GG(b, c, d, a, m[i+ 4], 20, -405537848);
      a = GG(a, b, c, d, m[i+ 9],  5,  568446438);
      d = GG(d, a, b, c, m[i+14],  9, -1019803690);
      c = GG(c, d, a, b, m[i+ 3], 14, -187363961);
      b = GG(b, c, d, a, m[i+ 8], 20,  1163531501);
      a = GG(a, b, c, d, m[i+13],  5, -1444681467);
      d = GG(d, a, b, c, m[i+ 2],  9, -51403784);
      c = GG(c, d, a, b, m[i+ 7], 14,  1735328473);
      b = GG(b, c, d, a, m[i+12], 20, -1926607734);

      a = HH(a, b, c, d, m[i+ 5],  4, -378558);
      d = HH(d, a, b, c, m[i+ 8], 11, -2022574463);
      c = HH(c, d, a, b, m[i+11], 16,  1839030562);
      b = HH(b, c, d, a, m[i+14], 23, -35309556);
      a = HH(a, b, c, d, m[i+ 1],  4, -1530992060);
      d = HH(d, a, b, c, m[i+ 4], 11,  1272893353);
      c = HH(c, d, a, b, m[i+ 7], 16, -155497632);
      b = HH(b, c, d, a, m[i+10], 23, -1094730640);
      a = HH(a, b, c, d, m[i+13],  4,  681279174);
      d = HH(d, a, b, c, m[i+ 0], 11, -358537222);
      c = HH(c, d, a, b, m[i+ 3], 16, -722521979);
      b = HH(b, c, d, a, m[i+ 6], 23,  76029189);
      a = HH(a, b, c, d, m[i+ 9],  4, -640364487);
      d = HH(d, a, b, c, m[i+12], 11, -421815835);
      c = HH(c, d, a, b, m[i+15], 16,  530742520);
      b = HH(b, c, d, a, m[i+ 2], 23, -995338651);

      a = II(a, b, c, d, m[i+ 0],  6, -198630844);
      d = II(d, a, b, c, m[i+ 7], 10,  1126891415);
      c = II(c, d, a, b, m[i+14], 15, -1416354905);
      b = II(b, c, d, a, m[i+ 5], 21, -57434055);
      a = II(a, b, c, d, m[i+12],  6,  1700485571);
      d = II(d, a, b, c, m[i+ 3], 10, -1894986606);
      c = II(c, d, a, b, m[i+10], 15, -1051523);
      b = II(b, c, d, a, m[i+ 1], 21, -2054922799);
      a = II(a, b, c, d, m[i+ 8],  6,  1873313359);
      d = II(d, a, b, c, m[i+15], 10, -30611744);
      c = II(c, d, a, b, m[i+ 6], 15, -1560198380);
      b = II(b, c, d, a, m[i+13], 21,  1309151649);
      a = II(a, b, c, d, m[i+ 4],  6, -145523070);
      d = II(d, a, b, c, m[i+11], 10, -1120210379);
      c = II(c, d, a, b, m[i+ 2], 15,  718787259);
      b = II(b, c, d, a, m[i+ 9], 21, -343485551);

      a = (a + aa) >>> 0;
      b = (b + bb) >>> 0;
      c = (c + cc) >>> 0;
      d = (d + dd) >>> 0;
    }

    return crypt.endian([a, b, c, d]);
  };

  // Auxiliary functions
  md5._ff  = function (a, b, c, d, x, s, t) {
    var n = a + (b & c | ~b & d) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };
  md5._gg  = function (a, b, c, d, x, s, t) {
    var n = a + (b & d | c & ~d) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };
  md5._hh  = function (a, b, c, d, x, s, t) {
    var n = a + (b ^ c ^ d) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };
  md5._ii  = function (a, b, c, d, x, s, t) {
    var n = a + (c ^ (b | ~d)) + (x >>> 0) + t;
    return ((n << s) | (n >>> (32 - s))) + b;
  };

  // Package private blocksize
  md5._blocksize = 16;
  md5._digestsize = 16;

  module.exports = function (message, options) {
    if (message === undefined || message === null)
      throw new Error('Illegal argument ' + message);

    var digestbytes = crypt.wordsToBytes(md5(message, options));
    return options && options.asBytes ? digestbytes :
        options && options.asString ? bin.bytesToString(digestbytes) :
        crypt.bytesToHex(digestbytes);
  };

})();


/***/ }),

/***/ 20:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AuthModule = void 0;
const common_1 = __webpack_require__(6);
const auth_controller_1 = __webpack_require__(21);
const auth_service_1 = __webpack_require__(22);
const passport_1 = __webpack_require__(27);
const jwt_1 = __webpack_require__(23);
const config_1 = __webpack_require__(15);
const users_module_1 = __webpack_require__(8);
const users_service_1 = __webpack_require__(9);
const typeorm_1 = __webpack_require__(7);
const users_entity_1 = __webpack_require__(14);
const typeorm_ex_decorator_1 = __webpack_require__(19);
const users_repository_1 = __webpack_require__(11);
const jwt_access_guard_1 = __webpack_require__(26);
const jwt_refresh_strategy_1 = __webpack_require__(32);
const jwt_refresh_guard_1 = __webpack_require__(28);
const rate_limit_module_1 = __webpack_require__(30);
let AuthModule = class AuthModule {
};
AuthModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([users_entity_1.User]),
            typeorm_ex_decorator_1.TypeOrmExModule.forCustomRepository([users_repository_1.UsersRepository]),
            passport_1.PassportModule.register({}),
            jwt_1.JwtModule.registerAsync({
                imports: [config_1.ConfigModule],
                useFactory: async (configService) => ({
                    secret: configService.get('JWT_ACCESS_SECRET'),
                    signOptions: {
                        expiresIn: configService.get('JWT_ACCESS_EXPIRATION_TIME'),
                    }
                }),
                inject: [config_1.ConfigService],
            }),
            (0, common_1.forwardRef)(() => users_module_1.UsersModule),
            rate_limit_module_1.APIRateLimitModule,
        ],
        controllers: [auth_controller_1.AuthController],
        providers: [auth_service_1.AuthService, users_service_1.UsersService, jwt_refresh_strategy_1.JwtRefreshStrategy, jwt_access_guard_1.JwtAccessAuthGuard, jwt_refresh_guard_1.JwtRefreshGuard],
    })
], AuthModule);
exports.AuthModule = AuthModule;


/***/ }),

/***/ 30:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.APIRateLimitModule = void 0;
const common_1 = __webpack_require__(6);
const throttler_1 = __webpack_require__(35);
const core_1 = __webpack_require__(4);
let APIRateLimitModule = class APIRateLimitModule {
};
APIRateLimitModule = __decorate([
    (0, common_1.Module)({
        imports: [
            throttler_1.ThrottlerModule.forRoot({
                ttl: 15,
                limit: 5,
            }),
        ],
        controllers: [],
        providers: [
            {
                provide: core_1.APP_GUARD,
                useClass: throttler_1.ThrottlerGuard,
            },
        ],
    })
], APIRateLimitModule);
exports.APIRateLimitModule = APIRateLimitModule;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("122ea59847fa3c7c1d83")
/******/ })();
/******/ 
/******/ }
;