import { Injectable, Logger, OnApplicationBootstrap, OnApplicationShutdown } from '@nestjs/common';
import { config } from '../config';
import { PrismaService } from '../prisma.service';

@Injectable()
export class SessionCleanupService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(SessionCleanupService.name);

  private timer?: NodeJS.Timeout;

  private running = false;

  constructor(private readonly db: PrismaService) {}

  onApplicationBootstrap() {
    const { cleanupInterval } = config();
    this.timer = setInterval(() => void this.runSafely(), cleanupInterval * 1000);
    this.timer.unref();
    void this.runSafely();
  }

  onApplicationShutdown() {
    if (this.timer) clearInterval(this.timer);
  }

  private async runSafely() {
    if (this.running) return;
    this.running = true;
    try {
      await this.purgeEndedSessions();
    } catch {
      this.logger.warn('Session cleanup failed, will retry on next interval');
    } finally {
      this.running = false;
    }
  }

  async purgeEndedSessions(now = new Date()): Promise<number> {
    const cutoff = new Date(now.getTime() - config().sessionRetention * 1000);
    const { count } = await this.db.session.deleteMany({
      where: { OR: [{ expiresAt: { lt: cutoff } }, { revokedAt: { lt: cutoff } }] },
    });
    return count;
  }
}
