export enum LogLevel {
	DEBUG = 0,
	INFO = 1,
	WARN = 2,
	ERROR = 3,
	NONE = 4,
}

// Query params that must never end up in logs (forward-auth is often configured via ?client_secret=...)
const REDACTED_PARAMS = ['client_secret', 'code', 'handoff'];

function redactUrl(raw: string): string {
	try {
		const url = new URL(raw);
		for (const param of REDACTED_PARAMS) {
			if (url.searchParams.has(param)) url.searchParams.set(param, '***');
		}
		return url.href;
	} catch {
		return raw;
	}
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
			message = `${message} | REQ: ${req.method} ${redactUrl(req.url)}, IP - ${req.headers.get('x-forwarded-for')}`;
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
