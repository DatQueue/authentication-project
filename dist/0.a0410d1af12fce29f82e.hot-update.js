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
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IPAuthentication = void 0;
const typeorm_1 = __webpack_require__(13);
const ip_auth_user_entity_1 = __webpack_require__(72);
let IPAuthentication = class IPAuthentication {
};
__decorate([
    (0, typeorm_1.PrimaryGeneratedColumn)(),
    __metadata("design:type", Number)
], IPAuthentication.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)({ default: false }),
    __metadata("design:type", Boolean)
], IPAuthentication.prototype, "isTwoFactorAuthenticated", void 0);
__decorate([
    (0, typeorm_1.OneToMany)(() => ip_auth_user_entity_1.IPAuthUser, ipAuthUser => ipAuthUser.ipAuth),
    __metadata("design:type", Array)
], IPAuthentication.prototype, "ipAuthUser", void 0);
IPAuthentication = __decorate([
    (0, typeorm_1.Entity)('ip_authentications')
], IPAuthentication);
exports.IPAuthentication = IPAuthentication;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("c83e8ebfab1205a9d9d4")
/******/ })();
/******/ 
/******/ }
;