import { Provider } from 'src/auth/google-oauth2/utils/provider.enum';
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

  @Column({ nullable: true, default: null })
  password: string;

  @Column({ nullable: true })
  currentRefreshToken: string;

  @Column({ type: 'datetime', nullable: true })
  currentRefreshTokenExp: Date;

  @Column({ nullable: true })
  twoFactorAuthenticationSecret: string;

  @Column({ default: false })
  isTwoFactorAuthenticationEnabled: boolean;

  @Column({ default: false })
  isSocialAccountRegistered: boolean;

  @Column({ name: 'social_provider', default: Provider.LOCAL })
  socialProvider: string;

  @Column({ name: 'external_id', nullable: true, default: null })
  externalId: string;

  @Column({ name: 'social_refresh_token', nullable: true, default: null })
  socialProvidedRefreshToken: string;
}
