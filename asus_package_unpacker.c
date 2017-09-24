// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <wchar.h>
#include <unistd.h>

struct file_header {
    char partname[32];
    char filename[32];
    unsigned long long int size;
    unsigned long long int unused;   // ?
    char model_id[8];
    unsigned long long int crc32;
};

void decode_partname (char *partname, char *decoded) {
    int i = 0;
    while (i < sizeof(((struct file_header *) 0)->partname)) {
        decoded[i/2] = partname[i];
        i += 2;
    }
}

int main (int argc, char **argv) {
    FILE *rawfile = NULL;
    char *PACKAGE_HEADER = "asus_package";
    size_t file_records_count = 100;
    char package_header[0x30] = {(char)0};
    size_t current_file = 0;
    size_t block = 1048576; // 1MB buffer
    char *buf = NULL;
    struct file_header *file_headers;

    if (argc != 2) {
        (void)fprintf(stderr, "Usage: %s {file.raw}\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    file_headers = (struct file_header *) calloc(file_records_count, sizeof(struct file_header));
    if (file_headers == NULL) {
        (void)fprintf(stderr, "Unable to allocate memory for file_headers\n");
        exit(EXIT_FAILURE);
    }

    buf = calloc (1, block);
    if (buf == NULL) {
        (void)fprintf(stderr, "Unable to allocate memory for i/o buffer\n");
        exit(EXIT_FAILURE);
    }

    rawfile = fopen(argv[1], "rb");
    if (!rawfile) {
        (void)fprintf(stderr, "Failed to open file '%s': %s\n", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    
    (void)fread(package_header, strlen(PACKAGE_HEADER), 1, rawfile);
    if(strncmp(package_header, PACKAGE_HEADER, sizeof(*PACKAGE_HEADER)) != 0) {
        (void)fprintf(stderr, "WARNING: Bad file '%s': expected file header '%s', got '%s', trying to continue anyway \n", argv[1], PACKAGE_HEADER, package_header);
    }

    // Read files headers table
    if(fseek(rawfile, 0x30, SEEK_SET) == -1) {
        (void)fprintf(stderr, "fseek to headers table failed for file '%s': %s\n", argv[1], strerror(errno));
        (void)fclose(rawfile);
        exit(EXIT_FAILURE);
    }
    if (fread(file_headers, sizeof(struct file_header), file_records_count, rawfile) != file_records_count) {
        (void)fprintf(stderr, "fread failed for file '%s': %s\n", argv[1], strerror(errno));
        (void)fclose(rawfile);
        exit(EXIT_FAILURE);
    }
    

    if (fseek(rawfile, 0x2800, SEEK_SET) == -1) {
        (void)fprintf(stderr, "fseek to file data start failed for file '%s': %s\n", argv[1], strerror(errno));
        (void)fclose(rawfile);
        exit(EXIT_FAILURE);
    }

    // Walk on headers table
    while (1) {
        char *filename;
        FILE *output;
        size_t left;
        size_t filename_buf_len;

        if (file_headers[current_file].size == 0 || current_file == file_records_count)
            break;

        decode_partname(file_headers[current_file].partname, file_headers[current_file].partname);
        (void)printf("Got file item:\npartname:'%s'\nfilename:%s\nsize: 0x%llX\nmodel_id='%8s'\nCRC32=0x%llX \n\n",
                     file_headers[current_file].partname, file_headers[current_file].filename, file_headers[current_file].size, (char *)file_headers[current_file].model_id, file_headers[current_file].crc32);

        filename_buf_len = strlen(file_headers[current_file].filename) + strlen((char *)file_headers[current_file].model_id) + 2;
        filename = calloc(1, filename_buf_len);
        if (filename == NULL) {
            (void)fprintf(stderr, "Unable to allocate memory for output file name\n");
            fclose(rawfile);
            free(buf);
            exit(EXIT_FAILURE);
        }
        if (strlen(file_headers[current_file].model_id))
            (void)snprintf(filename, filename_buf_len, "%s_%s", file_headers[current_file].model_id, file_headers[current_file].filename);
        else
            (void)snprintf(filename, filename_buf_len, "%s", file_headers[current_file].filename);
        
        output = fopen(filename, "wb");
        if (!output) {
            (void)fprintf(stderr, "Failed to open file '%s': %s\n", argv[1], strerror(errno));
            (void)fclose(rawfile);
            free(buf);
            exit(EXIT_FAILURE);
        }
        
        // Copy file data to output
        left = file_headers[current_file].size;
        while (left > 0) {
            size_t c;

            if (left < block)
                block = left;
            c = fread(buf, 1, block, rawfile);
            if ( c != block) {
                (void)fprintf(stderr, "Short fread at offset %ld from file '%s': expected %zud, got %zud (broken file?)\n", ftell(rawfile), argv[1], block, c);
                (void)fclose(rawfile);
                (void)fclose(output);
                free(buf);
                exit(EXIT_FAILURE);
            }

            c = fwrite(buf, 1, block, output);
            if (c != block) {
                (void)fprintf(stderr, "Short fwrite at offset %ld from file '%s': expected %zud, got %zud (broken file?)\n", ftell(output), filename, block, c);
                (void)fclose(rawfile);
                (void)fclose(output);
                free(buf);
                exit(EXIT_FAILURE);
            }
            left -= block;
        }
        free(filename);
        (void)fclose(output);
        ++current_file;
    }
    
    (void)printf("Done!\n");
    free(buf);
    (void)fclose(rawfile);
    exit(EXIT_SUCCESS);
}
