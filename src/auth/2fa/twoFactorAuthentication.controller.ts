import { UsersService } from "src/users/users.service";
import { TwoFactorAuthenticationService } from "./twoFactorAuthentication.service";
import { Body, ClassSerializerInterceptor, Controller, ForbiddenException, Post, Req, Res, UnauthorizedException, UseGuards, UseInterceptors } from "@nestjs/common";
import { Response } from "express";
import { JwtAccessAuthGuard } from "../guard/jwt-access.guard";
import RequestWithUser from "../interfaces/requestWithUser.interface";
import { TwoFactorAuthenticationCodeDto } from "./model/twoFactorAuthentication.dto";
import { AuthService } from "../auth.service";

@Controller('2fa')
@UseInterceptors(ClassSerializerInterceptor)
export class TwoFactorAuthenticationController {
  constructor(
    private readonly twoFactorAuthenticationService: TwoFactorAuthenticationService,
    private readonly userService: UsersService,
    private readonly authService: AuthService,
  ) {}

  @Post('generate')
  @UseGuards(JwtAccessAuthGuard)
  async register(@Res() res: Response, @Req() request: RequestWithUser) {
    const { otpAuthUrl } = await this.twoFactorAuthenticationService.generateTwoFactorAuthenticationSecret(request.user);

    return await this.twoFactorAuthenticationService.pipeQrCodeStream(res, otpAuthUrl);
  }

  @Post('turn-on')
  @UseGuards(JwtAccessAuthGuard)
  async turnOnTwoFactorAuthentication(
    @Req() req: RequestWithUser,
    @Body() twoFactorAuthenticationCodeDto: TwoFactorAuthenticationCodeDto
  ) {
    const isCodeValidated = await this.twoFactorAuthenticationService.isTwoFactorAuthenticationCodeValid(
      twoFactorAuthenticationCodeDto.twoFactorAuthenticationCode, req.user
    );
    if (!isCodeValidated) {
      throw new UnauthorizedException('Invalid Authentication-Code');
    }
    await this.userService.turnOnTwoFactorAuthentication(req.user.id);

    return {
      msg: "TwoFactorAuthentication turned on"
    }
  }

  @Post('turn-off')
  @UseGuards(JwtAccessAuthGuard)
  async turnOffTwoFactorAuthentication(
    @Req() req: RequestWithUser,
    @Body() twoFactorAuthenticationCodeDto: TwoFactorAuthenticationCodeDto
  ) {
    const isCodeValidated = await this.twoFactorAuthenticationService.isTwoFactorAuthenticationCodeValid(
      twoFactorAuthenticationCodeDto.twoFactorAuthenticationCode, req.user
    );
    if (!isCodeValidated) {
      throw new UnauthorizedException('Invalid Authentication-Code');
    }
    await this.userService.turnOffTwoFactorAuthentication(req.user.id);

    return {
      msg: "TwoFactorAuthentication turned off"
    }
  }

  @Post('authenticate')
  @UseGuards(JwtAccessAuthGuard)
  async authenticate(
    @Req() req: any,
    @Body() twoFactorAuthenticationCodeDto: TwoFactorAuthenticationCodeDto
  ) {
    const isCodeValidated = await this.twoFactorAuthenticationService.isTwoFactorAuthenticationCodeValid(
      twoFactorAuthenticationCodeDto.twoFactorAuthenticationCode, req.user
    );

    if (!req.user.isTwoFactorAuthenticationEnabled) {
      throw new ForbiddenException('Two-Factor Authentication is not enabled');
    }

    if (!isCodeValidated) {
      throw new UnauthorizedException('Invalid Authentication-Code');
    }

    const accessToken = await this.authService.generateAccessToken(req.user, true);
    console.log(req.user.isSecondFactorAuthenticated);
    req.res.setHeader('Set-Cookie', [accessToken]);

    return req.user;
  }
}