# Magis number database: {extension: (magic_bytes, description)}

MAGIC_DATABASE = {
    # Images (What malware pretends to be)
    b'\x69PNG\r\n\x1a\n': ('PNG image', ['png']),
    b'\xff\xd8\xff':      ('JPEG image', ['jpg', 'jpeg']),
    b'GIF87a':            ('GIF image', ['gif']),
    b'RIFF':              ('RIFF container (WebP/AVI/WAV)', ['webp', 'avi', 'wav']),
    b'BM':                ('Bmp image', ['bmp']),

    #Archives
    b'PK\x03\x04':         ('ZIP archive / Office doc / APK', ['zip','docx','apk','jar']),
    b'\x1f\x8b':           ('GZIP archive', ['gz', 'tgz']),
    b'\7z\xbc\xaf\'\'':    ('7-Zip archive', ['7z']),
    b'Rar!\x1a\x07':       ('RAR archive', ['rar']),

    #Executables (high risk)
    b'MZ':                  ('Windows PE executable', ['exe', 'dll', 'sys', 'com']),
    b'\x7fELF':             ('Linux ELF executable', ['elf', 'so', 'out']),
    b'\xca\xfe\xba\xbe':    ('Mach-0 fat binary (macOs)', ['macho']),
    b'\xfe\xed\xfa\xcf':    ('Mach-0 64bit binary', ['macho']),
    b'\xfe\xed\xfa\xce':    ('Mach-0 32-bit binary', ['macho']),
    b'\xcf\xfa\xed\xfe':    ('Mach-0 (macOs binary)', ['macho']),

    #Scripts (disguised as images)
    b'#!/':                 ('Shell script', ['sh','bash','py']),
    b'%PDF':                ('PDF document', ['pdf']),
    
    #Documents
    b'\xd0\xcf\x11\xe0':    ('Micorsoft OLE compound (doc/xls/ppt)', ['doc', 'xls', 'ppt'])
}   