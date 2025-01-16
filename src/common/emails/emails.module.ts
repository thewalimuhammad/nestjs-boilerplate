import { Module } from '@nestjs/common';
import { EmailsService } from './emails.service';
import { HandlebarsAdapter } from '@nestjs-modules/mailer/dist/adapters/handlebars.adapter';
import { MailerModule } from '@nestjs-modules/mailer';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { join } from 'path';

@Module({
  imports: [
    MailerModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        transport: {
          service: 'gmail',
          auth: {
            user: configService.get('MAIL_FROM'),
            pass: configService.get('MAIL_PASS'),
          },
          // debug: true, // show debug output
          // logger: true, // log information in console
        },
        defaults: {
          from: `"YOUR-COMPANY" <${configService.get('MAIL_FROM')}>`,
        },
        template: {
          dir: join(__dirname, '/templates/'),
          adapter: new HandlebarsAdapter(),
          options: {
            strict: true,
          },
        },
      }),
    }),
  ],
  providers: [EmailsService],
  exports: [EmailsService],
})
export class EmailsModule {}
