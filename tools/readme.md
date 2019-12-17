This directory contains some of the potentially useful tools involved in extracting information out of binary files.

These tools belongs to their respective programmers/developers. I do __not__ claim any ownership nor do I maintain these tools.

DTC is used for both decompilation as well as compilation of [device tree](https://elinux.org/Device_Tree_Reference) blobs that exists in SPI. DTC is maintained by their respective maintainers which can be found [here](https://git.kernel.org/pub/scm/utils/dtc/dtc.git/tree/README) and various contributors.

mdm.config contains what appears to be a LZW compressed XML file with extra information prepended to the beginning of the file. Initially, it was thought that the [firmware_extractor](https://forum.kitz.co.uk/index.php/topic,21936.msg378072.html#msg378072) may help extract information out. However, upon usage of the said tool, which did not work for this particular case, it was later discovered that by [stripping the first 60 blocks of the unwanted prepended junk](http://hacklu.com/blog/时隔2年？网站恢复正常/), and to [parse that through to python_lzw](https://abrazalaweb.net/2018/11/descomprimir-archivos-de-configuracion-lzw/), ignoring some errors during the extraction process, we end up with a human readable XML file.

cfe_generator_password, firmware_extractor, firmware_header_dump, and firmware_header_edit belongs to [Iam-TJ](https://github.com/iam-TJ).

python_lzw belongs to [joeatwork](https://github.com/joeatwork).

Sources of these tools are as follows
# dtc
* https://git.kernel.org/pub/scm/utils/dtc/dtc.git

# cfe_generate_password
* https://iam.tj/gitweb/gitweb.cgi?p=cfe_generate_password.git;a=summary
# firmware_extractor
* https://iam.tj/gitweb/gitweb.cgi?p=firmware_extractor.git;a=summary
# firmware_header_dump
* https://iam.tj/gitweb/gitweb.cgi?p=firmware_header_dump.git;a=summary
# firmware_header_edit
* https://iam.tj/gitweb/gitweb.cgi?p=firmware_header_edit.git;a=summary

# python-lzw
* https://github.com/joeatwork/python-lzw
