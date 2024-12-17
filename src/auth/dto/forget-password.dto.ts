import { IsEmail } from 'class-validator';

export class ForgetPasswordDto {
  @IsEmail({}, { message: 'Invalid Email' })
  email: string;
}
