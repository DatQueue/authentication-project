exports.id = 0;
exports.ids = null;
exports.modules = {

/***/ 74:
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {

"use strict";

var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.IpModule = void 0;
const typeorm_1 = __webpack_require__(7);
const common_1 = __webpack_require__(6);
const ip_auth_entity_1 = __webpack_require__(73);
const ip_auth_user_entity_1 = __webpack_require__(72);
const users_entity_1 = __webpack_require__(14);
const ip_service_1 = __webpack_require__(75);
let IpModule = class IpModule {
};
IpModule = __decorate([
    (0, common_1.Module)({
        imports: [
            typeorm_1.TypeOrmModule.forFeature([ip_auth_entity_1.IPAuthentication, ip_auth_user_entity_1.IPAuthUser, users_entity_1.User])
        ],
        providers: [ip_service_1.IpService]
    })
], IpModule);
exports.IpModule = IpModule;


/***/ }),

/***/ 75:
/***/ (() => {



/***/ })

};
exports.runtime =
/******/ function(__webpack_require__) { // webpackRuntimeModules
/******/ /* webpack/runtime/getFullHash */
/******/ (() => {
/******/ 	__webpack_require__.h = () => ("695075d23ca55794b91d")
/******/ })();
/******/ 
/******/ }
;