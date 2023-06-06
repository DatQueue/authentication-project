import { Controller, Get, Req, UseGuards } from "@nestjs/common";
import JwtTwoFactorGuard from "../auth/2fa/guard/jwt-twoFactor.guard";
import { User } from "../users/entities/users.entity";
import { UsersService } from "../users/users.service";

@Controller('test')
export class TwoFATestController {
  constructor(
    private readonly userService: UsersService,
  ) {}
  
  @UseGuards(JwtTwoFactorGuard)
  @Get('access-2fa')
  async accessWithTwoFA(
    @Req() req: any,
  ) {
    const user: User = await this.userService.findUserById(req.user.id);
    return user;
  }
}