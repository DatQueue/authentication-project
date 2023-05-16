import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { UsersModule } from './users/users.module';
import { User } from './users/entities/users.entity';
import { AuthModule } from './auth/auth.module';
import { ConfigModule } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { TwoFATestController } from './test.controller';

@Module({
  imports: [
    TypeOrmModule.forRoot({
      type: 'mysql',
      host: 'localhost',
      port: 3306,
      username: 'root',
      password: 'Janelevy0318@',
      database: 'auth-project',
      logging: true,
      autoLoadEntities: true,
      synchronize: true,
      entities: [User],
    }),
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    UsersModule,
    AuthModule,
    ScheduleModule.forRoot()
  ],
  controllers: [TwoFATestController],
  providers: [],
})
export class AppModule {}
