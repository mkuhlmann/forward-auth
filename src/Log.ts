export default class Log {
	info(message: string, ...args: any[]): void {
		console.info(`[INFO] ${message}`, ...args);
	}

	error(message: string, ...args: any[]): void {
		console.error(`[ERROR] ${message}`, ...args);
	}

	warn(message: string, ...args: any[]): void {
		console.warn(`[WARN] ${message}`, ...args);
	}

	debug(message: string, ...args: any[]): void {
		console.debug(`[DEBUG] ${message}`, ...args);
	}
}
