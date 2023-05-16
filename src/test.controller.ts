import { Controller, Get, UseGuards } from "@nestjs/common";
import JwtTwoFactorGuard from "./auth/2fa/guard/jwt-twoFactor.guard";

@Controller('test')
export class TwoFATestController {
  
  @UseGuards(JwtTwoFactorGuard)
  @Get('access-2fa')
  async accessWithTwoFA() {
    return {
      msg: "Succeed!",
    }
  }
}