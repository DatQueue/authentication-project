"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 55:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
var _a;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.SessionSerializer = void 0;
const passport_1 = __webpack_require__(32);
const common_1 = __webpack_require__(6);
const google_auth_service_1 = __webpack_require__(50);
let SessionSerializer = class SessionSerializer extends passport_1.PassportSerializer {
    constructor(googleAuthService) {
        super();
        this.googleAuthService = googleAuthService;
    }
    async serializeUser(user, done) {
        console.log(user, "serializeUser");
        done(null, user);
    }
    async deserializeUser(payload, done) {
        const user = await this.googleAuthService.findUserById(payload.id);
        console.log(user, "deserializeUser");
        return user ? done(null, user) : done(null, null);
    }
};
SessionSerializer = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof google_auth_service_1.GoogleAuthenticationService !== "undefined" && google_auth_service_1.GoogleAuthenticationService) === "function" ? _a : Object])
], SessionSerializer);
exports.SessionSerializer = SessionSerializer;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("0d0d4be8bd8df3616f62")
/******/ })();
/******/ 
/******/ }
;