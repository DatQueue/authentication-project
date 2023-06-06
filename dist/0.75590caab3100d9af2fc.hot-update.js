"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 51:
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
exports.GoogleStrategy = void 0;
const common_1 = __webpack_require__(6);
const passport_1 = __webpack_require__(32);
const passport_google_oauth20_1 = __webpack_require__(52);
const google_auth_service_1 = __webpack_require__(50);
let GoogleStrategy = class GoogleStrategy extends (0, passport_1.PassportStrategy)(passport_google_oauth20_1.Strategy) {
    constructor(googleAuthService) {
        super({
            clientID: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
            callbackURL: process.env.GOOGLE_CALLBACK_URL,
            scope: [process.env.GOOGLE_SCOPE_PROFILE, process.env.GOOGLE_SCOPE_EMAIL],
        });
        this.googleAuthService = googleAuthService;
    }
    authorizationParams() {
        return ({
            access_type: 'offline',
            prompt: 'select_account',
        });
    }
    async validate(accessToken, refreshToken, profile, done) {
        console.log(accessToken);
        console.log(refreshToken);
        console.log(profile);
        const { name, emails, provider } = profile;
        const socialLoginUser = {
            email: emails[0].value,
            firstName: name.givenName,
            lastName: name.familyName,
            socialProvider: provider,
            externalId: profile.id,
            accessToken,
            refreshToken,
        };
        try {
            const user = await this.googleAuthService.validateAndSaveUser(socialLoginUser);
            console.log(user, "strategy");
            done(null, user, accessToken);
        }
        catch (err) {
            done(err, false);
        }
    }
};
GoogleStrategy = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof google_auth_service_1.GoogleAuthenticationService !== "undefined" && google_auth_service_1.GoogleAuthenticationService) === "function" ? _a : Object])
], GoogleStrategy);
exports.GoogleStrategy = GoogleStrategy;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("893b8cc94a4508f5bf64")
/******/ })();
/******/ 
/******/ }
;