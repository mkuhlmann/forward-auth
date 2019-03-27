import fs from 'fs';


export default class Log {
	
	constructor() {
		this.fsLog = fs.createWriteStream('server.log', {'flags': 'a'});
	}
	
	static get LEVEL_DEBUG() { return 0; }
	static get LEVEL_INFO() { return 1; }
	static get LEVEL_WARN() { return 2; }
	static get LEVEL_ERROR() { return 3; }
	static get LEVEL_NOTSET() { return 10; }
	
	static get Level() {
		return Object.freeze({
			DEBUG: 0,
			INFO: 1,
			WARN: 2,
			ERROR: 3,
			NOTSET: 10
		});
	}
	
	static get LevelString() {
		return Object.freeze({
			0: 'DEBUG',
			1: 'INFO',
			2: 'WARN',
			3: 'ERROR',
			10: 'NOTSET'
		});
	}
	
	logWrite(line) {
		this.fsLog.write(line+"\n");
		console.log(line);
	}
	
	
	log(mod, line) {
		this.mLogLevel('info', mod, line);
	}
	
	log(level, namespace, message, obj) {
		let line = new Date().toISOString() + ` ${Log.LevelString[level]}: ${message}`;
		if(obj) line += ' ' + JSON.stringify(obj);
		this.logWrite(line);
	}
	
	logNs(level, namespace, message, obj) {
		let line = new Date().toISOString() + ` ${Log.LevelString[level]} [${namespace}]: ${message}`;
		if(obj) line += ' ' + JSON.stringify(obj);
		this.logWrite(line);
	}
	
	debug(message, obj) { this.log(this.LEVEL_DEBUG, message, obj); }
	debugNs(namespace, message, obj) { this.logNs(this.LEVEL_DEBUG, namespace, message, obj); }
}