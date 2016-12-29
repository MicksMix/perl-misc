#!/usr/bin/env perl
#
#
# Last Updated: May 27, 2013
#
# This script can accept a JAR file as input, and build a 
#  self-extracting EXE (via 7-zip sfx) for Windows that will
#  run the jar file with java.exe. eg:   java -jar malicious_file.jar
#
# Then this sfx EXE can be uploaded to a malware sandbox to be executed in the 
#  event that JAR extensions are not correctly associated with the java runtime
#
#
##
use strict;
my $file = shift;

if (!-f $file){
	print "You must pass a valid file in as an argument!\n";
	exit;
}

open my $inputfile, $file or die $!;
binmode $inputfile;

my ($buf, $data, $n);
if (($n = read $inputfile, $data, 4) !=0) {
	#print "$n bytes read\n";
	$buf .= $data;
} else {
	print "could not read file header!\n";
	exit;
}
close $inputfile or die $!;

my @hex = unpack ( "C*", substr($buf,0,4));
my $hexstr = join( '', @hex);

if ($hexstr =~ /^8075/){
	print "this has a PK header! probably a jar\n";
} else {
	print "this is not a jar file.\n";
	exit;
}

unlink($file.'.bat');
# write the batchfile that will be included in 7z
open my $batchfile, '>', "$file.bat";
print $batchfile "java -jar $file";
close $batchfile;


my $conf = $file.'.conf';

unlink $conf;
# write the config file used by 7z for sfx
open my $jarconf, '>', $conf;
print $jarconf ';!@Install@!UTF-8!'."\n";
print $jarconf 'Progress="No"'."\n";
print $jarconf 'ExecuteFile="'.$file.'.bat"'."\n";
print $jarconf ';!@InstallEnd@!'."\n";
close $jarconf;

# lets create the actual 7z file now
`7za a -y $file.7z $file.bat $file`;

if (!-f "$file.7z"){
	print "could not create 7z file!\n";

	unlink($file.'.bat');
	unlink($file.'.conf');
	exit;
}

# now lets create EXE
my $exename = $file."_jar.exe";
#`cat 7zS.sfx $file.conf $file.7z > $exename`;
`cat 7z.sfx $file.conf $file.7z > $exename`;
#copy /b "…\7-Zip\7zCon.sfx" + somefile.7z somefile.exe

#cleanup

unlink($file.'.conf');
unlink($file.'.7z');
unlink($file.'.bat');

# unlink($exename); #after submitting it
