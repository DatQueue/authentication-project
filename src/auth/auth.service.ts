import { BadRequestException, Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { User } from 'src/users/entities/users.entity';
import { UsersService } from 'src/users/users.service';
import { LoginDto } from './model/login.dto';
import { Payload } from './payload/payload.interface';
import { ConfigService } from '@nestjs/config';
import { RefreshTokenDto } from './model/refreshToken.dto';
import { Cron, CronExpression } from '@nestjs/schedule';


@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UsersService,
    private readonly jwtService: JwtService,  
    private readonly configService: ConfigService,
  ) {}
  
  async validateUser(loginDto: LoginDto): Promise<User> {
    const user = await this.userService.findUserByEmail(loginDto.email);

    if (!user) {
      throw new NotFoundException('User not found!')
    }

    if (!await bcrypt.compare(loginDto.password, user.password)) {
      throw new BadRequestException('Invalid credentials!');
    }

    return user;
  } 

  async getDecodedRefreshToken(refreshTokenDto: RefreshTokenDto): Promise<Payload> {
    const { refresh_token } = refreshTokenDto;
    const decodedRefreshToken = await this.jwtService.verify(refresh_token, { secret: process.env.JWT_REFRESH_SECRET }) as Payload;
    return decodedRefreshToken;
  }

  async refresh(refreshTokenDto: RefreshTokenDto): Promise<{ accessToken: string }> {
    
    const decodedRefreshToken = await this.getDecodedRefreshToken(refreshTokenDto);
    // Check if user exists
    const userId = decodedRefreshToken.id;

    const refreshTokenExpTime = parseInt(decodedRefreshToken.exp, 10) * 1000; //ms
    const currentTime = Date.now();
    console.log(refreshTokenExpTime, currentTime);

    if (refreshTokenExpTime < currentTime) {
      await this.userService.removeRefreshToken(userId);
    }

    const user = await this.userService.getUserIfRefreshTokenMatches(refreshTokenDto.refresh_token, userId);
    if (!user) {
      throw new UnauthorizedException('Invalid user!');
    }
    // Generate new access token
    const accessToken = await this.generateAccessToken(user);

    return {accessToken};
  }

  async getRefreshTokenValidityPeriod() {
    const currentTime: number = Date.now();
    const refreshTokenExpTime: number = (await this.userService.getCurrentRefreshTokenExp()).getTime();
    const refreshTokenValidityPeriod = refreshTokenExpTime - currentTime;
    return refreshTokenValidityPeriod;
  }

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT) 
  async removeExpiredTokens() {
    const currentTime = new Date().getTime();
    const usersWithExpiredTokens = await this.userService.findUsersWithExpiredTokens(currentTime);
    console.log(usersWithExpiredTokens);
    for (const user of usersWithExpiredTokens) {
      if (user.currentRefreshToken) {
        await this.userService.removeRefreshToken(user.id); 
      }
    }
  }

  async generateAccessToken(user: User, isSecondFactorAuthenticated = false): Promise<string> {
    const payload: Payload = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      isSecondFactorAuthenticated: isSecondFactorAuthenticated,
    }
    return this.jwtService.signAsync(payload);
  }

  async generateRefreshToken(user: User): Promise<string> {
    const payload: Payload = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
    }
    return this.jwtService.signAsync({id: payload.id}, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION_TIME'),
    });
  }

}
