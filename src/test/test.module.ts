import { Module } from '@nestjs/common';
import { TwoFATestController } from './test.controller';
import { UsersService } from 'src/users/users.service';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from 'src/users/entities/users.entity';
import { TypeOrmExModule } from 'src/common/repository-module/typeorm-ex.decorator';
import { UsersRepository } from 'src/users/repositories/users.repository';

@Module({
  imports: [
    TypeOrmModule.forFeature([User]),
    TypeOrmExModule.forCustomRepository([UsersRepository])
  ],
  controllers: [TwoFATestController],
  providers: [UsersService],
})
export class TwoFATestModule {}