import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import * as bcrypt from 'bcrypt';
import { Role } from 'src/constant/index.constant';

@Schema({ timestamps: true })
export default class User {
  @Prop()
  name: string;

  @Prop()
  email: string;

  @Prop({ enum: Role, default: Role.USER })
  role: Role;

  @Prop({
    set: (password: string) => bcrypt.hashSync(password, 10),
  })
  password: string;

  @Prop({ default: false })
  isVerified: boolean;

  @Prop({ default: false })
  isDeleted: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);
