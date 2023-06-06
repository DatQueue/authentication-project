"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 50:
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
exports.GoogleAuthenticationService = void 0;
const common_1 = __webpack_require__(6);
const users_service_1 = __webpack_require__(9);
const provider_enum_1 = __webpack_require__(15);
let GoogleAuthenticationService = class GoogleAuthenticationService {
    constructor(userService) {
        this.userService = userService;
    }
    async validateAndSaveUser(socialLoginInfoDto) {
        const { email } = socialLoginInfoDto;
        const existingUser = await this.userService.findUserByEmail(email);
        if (existingUser) {
            if (existingUser.socialProvider !== provider_enum_1.Provider.GOOGLE) {
                console.log(existingUser, "existingUser");
                return {
                    existingUser: existingUser,
                    msg: '해당 이메일을 사용중인 계정이 존재합니다.'
                };
            }
            else {
                return existingUser;
            }
        }
        const newUser = await this.userService.createSocialUser(socialLoginInfoDto);
        const updateUser = await this.userService.updateSocialUserInfo(newUser.id);
        console.log(updateUser, "updateUser");
        return updateUser;
    }
    async findUserById(id) {
        const user = await this.userService.findUserById(id);
        return user;
    }
};
GoogleAuthenticationService = __decorate([
    (0, common_1.Injectable)(),
    __metadata("design:paramtypes", [typeof (_a = typeof users_service_1.UsersService !== "undefined" && users_service_1.UsersService) === "function" ? _a : Object])
], GoogleAuthenticationService);
exports.GoogleAuthenticationService = GoogleAuthenticationService;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("d64de4c4e8d8bd22f552")
/******/ })();
/******/ 
/******/ }
;