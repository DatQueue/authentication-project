export interface Payload {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  iat?: string;
  exp?: string;
  isSecondFactorAuthenticated: boolean;
}