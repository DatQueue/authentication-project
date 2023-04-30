import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { UsersService } from "src/users/users.service";
import { Payload } from "../payload/payload.interface";
import { User } from "src/users/entities/users.entity";
import { Injectable, UnauthorizedException } from "@nestjs/common";
import { Request } from "express";

const cookieExtractor = (req: Request) => {
  let token = null;
  if (req && req.cookies) {
    token = req.cookies['access_token'];
  }
  return token;
}

@Injectable()
export class JwtAccessStrategy extends PassportStrategy(Strategy, 'jwt-access-token') {
  constructor(private readonly userService: UsersService) {
    super({
      jwtFromRequest: ExtractJwt.fromExtractors([
        ExtractJwt.fromAuthHeaderAsBearerToken(),
        cookieExtractor,
      ]),
      secretOrKey: process.env.JWT_ACCESS_SECRET,
    })
  }

  async validate(payload: Payload): Promise<User> {
    const { id } = payload;
    const user = await this.userService.findUserById(id);

    if (!user) {
      throw new UnauthorizedException();
    }

    return user;
  }
}