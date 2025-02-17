import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { JwtStrategy } from './strategies/jwt.strategy';
import { mongooseFeatures } from 'src/config/mongoose-features.config';
import { EmailsModule } from 'src/common/emails/emails.module';

@Module({
  imports: [
    mongooseFeatures,
    PassportModule,
    JwtModule.register({
      secret: process.env.JWT_SECRET_KEY,
      signOptions: { expiresIn: process.env.JWT_EXPIRATION },
    }),
    EmailsModule,
  ],
  controllers: [AuthController],
  providers: [AuthService, JwtStrategy],
  exports: [AuthService],
})
export class AuthModule {}
