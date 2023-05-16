"use strict";
exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 72:
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
exports.IPAuthUser = void 0;
const typeorm_1 = __webpack_require__(13);
const ip_auth_entity_1 = __webpack_require__(73);
const users_entity_1 = __webpack_require__(14);
let IPAuthUser = class IPAuthUser {
    beforeInsert() {
        const userId = this.user.id;
        const ipAuthId = this.ipAuth.id;
        this.id = String(userId).padStart(7, "0") + String(ipAuthId).padStart(7, "0");
    }
};
__decorate([
    (0, typeorm_1.PrimaryColumn)(),
    __metadata("design:type", String)
], IPAuthUser.prototype, "id", void 0);
__decorate([
    (0, typeorm_1.Column)(),
    __metadata("design:type", String)
], IPAuthUser.prototype, "frequentlyUsedIp", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => users_entity_1.User, user => user.ipAuthUser, { onDelete: 'CASCADE' }),
    __metadata("design:type", typeof (_a = typeof users_entity_1.User !== "undefined" && users_entity_1.User) === "function" ? _a : Object)
], IPAuthUser.prototype, "user", void 0);
__decorate([
    (0, typeorm_1.ManyToOne)(() => ip_auth_entity_1.IPAuthentication, ipAuth => ipAuth.ipAuthUser, { onDelete: 'CASCADE' }),
    __metadata("design:type", typeof (_b = typeof ip_auth_entity_1.IPAuthentication !== "undefined" && ip_auth_entity_1.IPAuthentication) === "function" ? _b : Object)
], IPAuthUser.prototype, "ipAuth", void 0);
__decorate([
    (0, typeorm_1.BeforeInsert)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", void 0)
], IPAuthUser.prototype, "beforeInsert", null);
IPAuthUser = __decorate([
    (0, typeorm_1.Entity)('ip_auth_user')
], IPAuthUser);
exports.IPAuthUser = IPAuthUser;


/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("f4b89307ab2b8b6dd26b")
/******/ })();
/******/ 
/******/ }
;