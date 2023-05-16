import { Column, Entity, PrimaryGeneratedColumn } from 'typeorm';

@Entity({name:'users'})
export class User {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({name:'firstname'})
  firstName: string;

  @Column({name:'lastname'})
  lastName: string;

  @Column({name:'email'})
  email: string;

  @Column()
  password: string;

  @Column({ nullable: true })
  currentRefreshToken: string;

  @Column({ type: 'datetime', nullable: true })
  currentRefreshTokenExp: Date;

  @Column({ nullable: true })
  twoFactorAuthenticationSecret: string;

  @Column({ default: false })
  isTwoFactorAuthenticationEnabled: boolean;
}
