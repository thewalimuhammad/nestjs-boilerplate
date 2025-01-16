import { Injectable } from '@nestjs/common';
import { SignupEmailDto } from './dto/signup-email.dto';
import { MailerService } from '@nestjs-modules/mailer';
import { ForgetPasswordDto } from './dto/forget-password.dto';
import { UpdateEmailDto } from './dto/update-email.dto';
import { UpdatePasswordDto } from './dto/update-password.dto';

@Injectable()
export class EmailsService {
  constructor(private mailerService: MailerService) {}

  async SignupEmail(body: SignupEmailDto): Promise<boolean> {
    try {
      const { name, email, otp } = body;
      const emailSent = await this.mailerService.sendMail({
        to: email,
        subject: 'Welcome to YOUR-COMPANY - Email Verification',
        template: 'signup-email', // `.hbs` extension is appended automatically
        context: {
          name,
          otp,
        },
      });
      return emailSent ? true : false;
    } catch (error) {
      throw error;
    }
  }

  async forgetPasswordEmail(
    createEmailDto: ForgetPasswordDto,
  ): Promise<boolean> {
    try {
      const { name, email, otp } = createEmailDto;
      const emailSent = await this.mailerService.sendMail({
        to: email,
        subject: 'Forgot or Reset Password at YOUR-COMPANY',
        template: 'forget-password',
        context: {
          otp,
          name,
        },
      });
      return emailSent ? true : false;
    } catch (error) {
      throw error;
    }
  }

  async updateEmail(updateEmail: UpdateEmailDto): Promise<boolean> {
    try {
      const { name, email, newEmail } = updateEmail;
      const emailSent = await this.mailerService.sendMail({
        to: email,
        subject: 'Email updated at YOUR-COMPANY',
        template: 'update-email',
        context: {
          name,
          email,
          newEmail,
        },
      });
      return emailSent ? true : false;
    } catch (error) {
      throw error;
    }
  }

  async updatePasswordEmail(
    updatePassword: UpdatePasswordDto,
  ): Promise<boolean> {
    try {
      const { name, email } = updatePassword;
      const emailSent = await this.mailerService.sendMail({
        to: email,
        subject: 'Password updated at YOUR-COMPANY',
        template: 'update-password',
        context: {
          name,
          email,
        },
      });
      return emailSent ? true : false;
    } catch (error) {
      throw error;
    }
  }
}
