import fs from 'fs';


export default class Log {
	
	constructor() {
		this.fsLog = fs.createWriteStream('server.log', {'flags': 'a'});
		this.level = 5;
	}
	
	static get LEVEL_ERROR() { return 0; }
	static get LEVEL_WARN() { return 1; }
	static get LEVEL_INFO() { return 2; }
	static get LEVEL_HTTP() { return 3; }
	static get LEVEL_VERBOSE() { return 4; }
	static get LEVEL_DEBUG() { return 5; }
	static get LEVEL_SILLY() { return 6; }
	
	static get Level() {
		return Object.freeze({
			ERROR: 0,
			WARN: 1,
			INFO: 2,
			HTTP: 3,
			VERBOSE: 4,
			DEBUG: 5,
			SILLY: 6
		});
	}
	
	static get LevelString() {
		return Object.freeze({
			0: 'ERROR',
			1: 'WARN',
			2: 'INFO',
			3: 'HTTP',
			4: 'VERBOSE',
			5: 'DEBUG',
			6: 'SILLY'
		});
	}
	
	logWrite(line) {
		this.fsLog.write(line+"\n");
		console.log(line);
	}
	
	log(level, message, ...obj) {
		if(!Number.isInteger(level)) {
			level = Log.Level[level.toUpperCase()];
		}
		
		if(level > this.level) return;

		let line = new Date().toISOString() + ` ${Log.LevelString[level].padEnd(5)} | ${message}`;
		if(obj && obj.length > 0) line += ' ' + JSON.stringify(obj);
		this.logWrite(line);
	}
	
	/**
	 * Write to log with Level DEBUG
	 * @param {string} message
	 * @param {any[]} obj
	 */
	debug(message, ...obj) { this.log(Log.LEVEL_DEBUG, message, ...obj); }
	/**
	 * Write to log with Level INFO
	 * @param {string} message
	 * @param {any[]} obj
	 */
	info(message, ...obj) { this.log(Log.LEVEL_INFO, message, ...obj); }
	/**
	 * Write to log with Level WARN
	 * @param {string} message
	 * @param {any[]} obj
	 */
	warn(message, ...obj) { this.log(Log.LEVEL_WARN, message, ...obj); }
	/**
	 * Write to log with Level ERROR
	 * @param {string} message
	 * @param {any[]} obj
	 */
	error(message, ...obj) { this.log(Log.LEVEL_ERROR, message, ...obj); }
}