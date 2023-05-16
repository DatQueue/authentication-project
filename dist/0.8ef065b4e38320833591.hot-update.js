"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 73:
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
var _a, _b;
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.TwoFactorAuthenticationService = void 0;
const config_1 = __webpack_require__(15);
const users_service_1 = __webpack_require__(9);
const otplib_1 = __webpack_require__(74);
const qrcode_1 = __webpack_require__(82);
const common_1 = __webpack_require__(6);
let TwoFactorAuthenticationService = class TwoFactorAuthenticationService {
    constructor(userService, configService) {
        this.userService = userService;
        this.configService = configService;
    }
    async generateTwoFactorAuthenticationSecret(user) {
        const secret = otplib_1.authenticator.generateSecret();
        console.log(secret);
        const otpAuthUrl = otplib_1.authenticator.keyuri(user.email, this.configService.get('TWO_FACTOR_AUTHENTICATION_APP_NAME'), secret);
        await this.userService.setTwoFactorAuthenticationSecret(secret, user.id);
        return {
            secret,
            otpAuthUrl
        };
    }
    async pipeQrCodeStream(stream, otpAuthUrl) {
        return (0, qrcode_1.toFileStream)(stream, otpAuthUrl);
    }
    async isTwoFactorAuthenticationCodeValid(twoFactorAuthenticationCode, user) {
        if (!user.twoFactorAuthenticationSecret) {
            return false;
        }
        return otplib_1.authenticator.verify({
            token: twoFactorAuthenticationCode,
            secret: user.twoFactorAuthenticationSecret,
        });
    }
};
TwoFactorAuthenticationService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object, typeof (_b = typeof config_1.ConfigService !== "undefined" && config_1.ConfigService) === "function" ? _b : Object])
], TwoFactorAuthenticationService);
exports.TwoFactorAuthenticationService = TwoFactorAuthenticationService;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("181adf88729861defbe7")
/******/ })();
/******/ 
/******/ }
;