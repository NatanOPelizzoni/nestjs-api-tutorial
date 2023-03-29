import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { Prisma } from '@prisma/client'
import { AuthDto } from "./dto";
import * as argon from 'argon2';

@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService) { }

    async signUp(dto: AuthDto) {
        //Generate the password hash
        const hash = await argon.hash(dto.password);
        //save the new user in the db
        try {
            const user = await this.prisma.user.create({
                data: {
                    email: dto.email,
                    hash: hash,
                }
            });
            delete user.hash;
            //return the saved user
            return user;
        } catch (error) {
            if (error instanceof Prisma.PrismaClientKnownRequestError) {
                if (error.code === 'P2002') {
                    throw new ForbiddenException(
                        'Email already exists',
                    );
                }
            }
            throw error;
        }
    }

    async signIn(dto: AuthDto) {
        // find the user by email
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email,
            }
        });
        // if user does not exist throw exception
        if (!user) {
            throw new ForbiddenException('Invalid credentials');
        }
        // compare the password with the hash
        const pwMatches = await argon.verify(user.hash, dto.password);
        // if password does not match throw exception
        if (!pwMatches) {
            throw new ForbiddenException('Invalid credentials');
        }
        // return the user
        delete user.hash;
        return user;
    }
}