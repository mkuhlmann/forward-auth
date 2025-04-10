export enum LogLevel {
	DEBUG = 0,
	INFO = 1,
	WARN = 2,
	ERROR = 3,
	NONE = 4,
}

export default class Log {
	private logLevel: LogLevel = LogLevel.INFO;

	setLogLevel(level: LogLevel): void {
		this.logLevel = level;
	}

	private getFormattedTime(): string {
		const now = new Date();
		return now.toISOString();
	}

	private getFormattedMessage(severity: string, message: string, ...args: any[]): string {
		if (args[0] instanceof Request) {
			const req = args[0] as Request;
			message = `${message} | REQ: ${req.method} ${req.url}, IP - ${req.headers.get('x-forwarded-for')}`;
			args = args.slice(1);
		}

		const formattedArgs = args.map((arg) => (typeof arg === 'object' ? JSON.stringify(arg) : arg)).join(' ');
		return `[${this.getFormattedTime()}] [${severity}] ${message} ${formattedArgs}`;
	}

	info(message: string, ...args: any[]): void {
		if (this.logLevel <= LogLevel.INFO) {
			console.info(this.getFormattedMessage('INFO', message, ...args));
		}
	}

	error(message: string, ...args: any[]): void {
		if (this.logLevel <= LogLevel.ERROR) {
			console.error(this.getFormattedMessage('ERROR', message, ...args));
		}
	}

	warn(message: string, ...args: any[]): void {
		if (this.logLevel <= LogLevel.WARN) {
			console.warn(this.getFormattedMessage('WARN', message, ...args));
		}
	}

	debug(message: string, ...args: any[]): void {
		if (this.logLevel <= LogLevel.DEBUG) {
			console.debug(this.getFormattedMessage('DEBUG', message, ...args));
		}
	}
}
