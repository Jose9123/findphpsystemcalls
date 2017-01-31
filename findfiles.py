#!/usr/bin/python -tt
import os, re, sys, time, datetime, math

class Finder:
    def logMatchesFound(self, file, pattern, line):
        if self.outputToScreen:
            print ("\n\nPattern found in: " + file + "\nPattern: " + pattern + "\nLine: " + line)
        if self.logToFile:
            self.outputfile.write("Pattern found in: " + file + "\nPattern: " + pattern + "\nLine: " + line + '\n\n')
            self.csvfile.write(file + "," + pattern + "," + line + '\n')

    def checkForPHPSystemCalls(self, dir, filename):
        global pattern_matches
        fullfilepath = os.path.abspath(os.path.join(dir, filename))
        if os.access(fullfilepath, os.R_OK):
            file = open(fullfilepath)
            filetext = file.read()
            file.seek(0)
            if self.hasInputParamaters(filetext):
                for line in file:
                    if (str.strip(line)[-1:] == ';'):
                        for pattern in self.function_patterns:
                            pattern_regex = r'([\W])'+ re.escape(pattern) + r'[\s]*\(.*\)'
                            if re.search(pattern_regex, line, re.IGNORECASE):
                                self.pattern_matches += 1
                                self.logMatchesFound(fullfilepath, pattern + ' ()', line.rstrip())
                    backtick_regex = '`.*`'
                    if re.search(backtick_regex, line, re.IGNORECASE):
                        match = re.search(backtick_regex, line, re.IGNORECASE)
                        self.pattern_matches += 1
                        self.logMatchesFound(fullfilepath, match.group(0), line.rstrip())
            file.close()

    def hasInputParamaters(self, text):
        filetext = text
        for pattern in self.input_patterns:
            pattern_regex = re.escape(pattern)
            if re.search(pattern_regex, filetext, re.IGNORECASE):
                return True
        return False

    def isPHPfile(self, dir, filename):
        global php_file_count
        fullfilepath = os.path.abspath(os.path.join(dir, filename))
        if re.match(r'[a-zA-Z0-9]+.*\.php$', filename) and os.path.isfile(fullfilepath):
            self.php_file_count += 1
            return True
        return False

    def dirHasPHPfiles(self, dir):
        for f in os.listdir(dir):
            if re.search('.php', f):
                return True
        return False
    def is_binary(filename):
        """
        Return true if the given filename appears to be binary.
        File is considered to be binary if it contains a NULL byte.
        FIXME: This approach incorrectly reports UTF-16 as binary.
        """
        with open(filename, 'rb') as f:
            for block in f:
                if '\0' in block:
                    return True
        return False

    def scan_cgibin(self, webfolder):
        perl_shell_functions = ['ReadParse', 'system', 'exec']
        cgibin_matches = 0
        cgibinDir = os.path.abspath(os.path.join(webfolder, os.pardir, 'cgi-bin'))
        if self.logToFile:
            self.outputfile.write('\n\ncgi-bin scripts that have input parameters:\n' + ('-' * 40) + '\n')
        print 'Scanning: ' + cgibinDir
        for dirName, subdirList, filenames in os.walk(cgibinDir):
            for filename in filenames:
                if os.access(os.path.join(cgibinDir, filename), os.R_OK) and !(is_binary(filename)):
                    file = open(os.path.join(dirName, filename))
                    filetext = file.read()
                    file.seek(0)
                    for line in file:
                        for function in perl_shell_functions:                
                            pattern_regex = re.escape(function) + r'[\s]*\(.*\)'
                            if re.search(pattern_regex, line, re.IGNORECASE):
                                cgibin_matches += 1
                                match = re.search(pattern_regex, line, re.IGNORECASE)
                                self.logMatchesFound(os.path.join(cgibinDir, filename), match.group(0), line.rstrip())
                        backtick_regex = re.escape('`.*`')
                        if re.search(backtick_regex, line, re.IGNORECASE):
                            match = re.search(backtick_regex, line, re.IGNORECASE)
                            self.cgibin_matches += 1
                            self.logMatchesFound(os.path.join(cgibinDir, filename), match.group(0), line.rstrip())
        return cgibin_matches
                        
    def fin(self, current_dir, current_file, php_file_count, cgibin_matches):
        totalTime = int(round(time.time()-self.startTime))
        if self.logToFile:
            self.outputfile.write('\n\nDirectories: %4d \tFiles: %2d \tPHP files: %d' % (current_dir, current_file, php_file_count))
            self.outputfile.write('\nPatterns detected: ' + str(self.pattern_matches))
            self.outputfile.write('\ncgibin matches: ' + str(cgibin_matches))
            self.outputfile.write('\nElapsed time: ' + time.strftime("%H:%M:%S", time.gmtime(totalTime)))
            self.outputfile.flush()
            self.csvfile.flush()
            self.outputfile.close()
            self.csvfile.close()
        print ('\nDone: ' + '\tPHP files scanned: ' + str(self.php_file_count) + '\t\tPatterns detected: ' + str(self.pattern_matches))
        print ('\ncgi-bin matches: ' + str(cgibin_matches))    
        print 'Elapsed time: ' + time.strftime("%H:%M:%S", time.gmtime(totalTime))

    def scan(self, webfolder):
        self.startTime = time.time()
        self.function_patterns = ['exec','passthru','shell_exec','system','proc_open','popen','curl_exec','curl_multi_exec','parse_ini_file','show_source']
        self.input_patterns = ['$_GET', '$_POST', '$_REQUEST']
        self.php_file_count = 0
        self.pattern_matches = 0
    
        self.logToFile = True
        self.outputToScreen = True
        webroot = webfolder
     
        if self.logToFile:
            self.outputfile = open(webroot + '_php_system_calls_' + time.strftime("%Y%m%d-%H%M%S") + '.log', 'wb+')
            self.csvfile = open(webroot + '_php_system_calls_' + time.strftime("%Y%m%d-%H%M%S") + '.csv', 'wb+')

        webrootpath = {  'webdev'  : '/usr2/nco/ncowebdev/htdocs',
                'webdev2'  : '/usr2/www/htdocs',
                'wpc'   : '/home/www/wpc/htdocs',
                'nco'   : '/home/www/nco/htdocs',
                'mag'   : '/home/www/nco_mag/prod/htdocs',
                'opc'   : '/home/www/opc/htdocs',
                'cpc'   : '/home/www/cpc/htdocs',
                'emc'   : '/home/www/emc/htdocs'    }          
        print 'Scanning: ' + webrootpath[webroot]
        current_file = 0
        current_dir = 0 
        for dirName, subdirList, fileList in os.walk(webrootpath[webroot]):
            current_dir += 1
            sys.stdout.flush()
            sys.stdout.write('Directories: %4d \tFiles: %2d \tPHP files: %d\r' % (current_dir, current_file, self.php_file_count))
            sys.stdout.flush()
            if self.dirHasPHPfiles(dirName):
                for filename in fileList:
                    current_file += 1               
                    if self.isPHPfile(dirName, filename):
                        self.checkForPHPSystemCalls(dirName, filename)
                if self.logToFile:
                    self.outputfile.flush()
                    self.csvfile.flush()
        cgibin_matches = self.scan_cgibin(webrootpath[webroot])
        self.fin(current_dir, current_file, self.php_file_count, cgibin_matches)

    def __init__(self):
        pass

def main(): 
    finder = Finder()
    webfolders = ['webdev', 'webdev2']
    # webfolders = ['wpc', 'nco', 'mag', 'opc', 'cpc']
    # webfolders = ['emc']
    for folder in webfolders:
        finder.scan(folder)

if __name__ == '__main__':
    main()