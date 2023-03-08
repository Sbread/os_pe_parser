#include <iostream>
#include <fstream>
#include <cstring>
#include <vector>

size_t find_raw(std::vector<std::vector<size_t> > &sections, size_t rva) {
    for (auto it: sections) {
        if (it[0] <= rva && rva < it[0] + it[1]) {
            return it[2] + rva - it[0];
        }
    }
    return 0;
}

size_t read(std::ifstream &pe, size_t start_pos, size_t cnt) {
    pe.seekg(start_pos, pe.beg);
    size_t res = 0;
    pe.read((char *) &res, cnt);
    return res;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        std::cout << "Expected mode and file to check\n";
        return 0;
    }
    std::ifstream pe(argv[2]);
    if (!pe.is_open()) {
        std::cout << "cannot open file\n";
        return 0;
    }
    if (strcmp(argv[1], "is-pe") == 0) {
        size_t pos = read(pe, 0x3C, 4);
        pe.seekg(pos, pe.beg);
        char filetype[4];
        pe.read(filetype, 4);
        if (filetype[0] != 'P' || filetype[1] != 'E' || filetype[2] != '\0' || filetype[3] != '\0') {
            pe.close();
            std::cout << "Not PE\n";
            return 1;
        }
        std::cout << "PE\n";
        pe.close();
        return 0;
    }

    size_t coff_header_start = read(pe, 0x3C, 4) + 4;
    size_t number_of_sections = read(pe, coff_header_start + 2, 2);
    size_t opt_header_start = coff_header_start + 20;
    size_t header_start = opt_header_start + 240;
    size_t section_virtual_size;
    size_t section_rva;
    size_t section_raw;
    std::vector<std::vector<size_t> > sections(number_of_sections);
    for (size_t i = 0; i < number_of_sections; ++i) {
        section_virtual_size = read(pe, header_start + i * 40 + 0x8, 4);
        section_rva = read(pe, header_start + i * 40 + 0xC, 4);
        section_raw = read(pe, header_start + i * 40 + 0x14, 4);
        sections[i] = {section_rva, section_virtual_size, section_raw};
    }

    if (strcmp(argv[1], "import-functions") == 0) {
        size_t import_table_rva = read(pe, opt_header_start + 0x78, 4);
        size_t import_raw = find_raw(sections, import_table_rva);
        for (size_t i = 0;; i += 20) {
            size_t import_lookup_table_rva = read(pe, import_raw + i, 4);
            size_t time_date_stamp = read(pe, import_raw + i + 4, 4);
            size_t forwarder_chain = read(pe, import_raw + i + 8, 4);
            size_t library_name_rva = read(pe, import_raw + i + 12, 4);
            size_t import_adress_table_rva = read(pe, import_raw + i + 16, 4);
            if (import_lookup_table_rva == 0 && time_date_stamp == 0
                && forwarder_chain == 0 && library_name_rva == 0 && import_adress_table_rva == 0)
                break;
            size_t library_name_raw = find_raw(sections, library_name_rva);
            pe.seekg(library_name_raw, pe.beg);

            char tmp;
            while (true) {
                pe.get(tmp);
                if (tmp == '\0') break;
                std::cout << tmp;
            }
            std::cout << '\n';
            size_t import_lookup_table_raw = find_raw(sections, import_lookup_table_rva);
            size_t j = 0;
            while (true) {
                size_t first_pat_ilt = read(pe, import_lookup_table_raw + j, 4);
                size_t second_part_ilt = read(pe, import_lookup_table_raw + j + 4, 4);
                if (first_pat_ilt == 0 && second_part_ilt == 0) {
                    break;
                }
                size_t sign_bit = second_part_ilt >> 31;
                if (sign_bit == 0) {
                    size_t name_table_rva = first_pat_ilt;
                    size_t name_table_raw = find_raw(sections, name_table_rva);
                    pe.seekg(name_table_raw + 2, pe.beg);
                    std::cout << "    ";
                    while (true) {
                        pe.get(tmp);
                        if (tmp == '\0') break;
                        std::cout << tmp;
                    }
                    std::cout << '\n';
                }
                j += 8;
            }
        }
        pe.close();
        return 0;
    } else if (strcmp(argv[1], "export-functions") == 0) {
        size_t export_table_rva = read(pe, opt_header_start + 112, 4);
        size_t export_table_raw = find_raw(sections, export_table_rva);
        size_t number_of_name_pointers = read(pe, export_table_raw + 24, 4);
        size_t export_name_pointer_rva = read(pe, export_table_raw + 32, 4);
        size_t export_name_pointer_raw = find_raw(sections, export_name_pointer_rva);
        size_t pointer_into_export_name_table_rva = read(pe, export_name_pointer_raw, 4);
        size_t pointer_into_export_name_table_raw = find_raw(sections,
                                                             pointer_into_export_name_table_rva); // first entry
        pe.seekg(pointer_into_export_name_table_raw, pe.beg);
        char tmp;
        for (size_t i = 0; i < number_of_name_pointers; ++i) {
            while (true) {
                pe.get(tmp);
                if (tmp == '\0') break;
                std::cout << tmp;
            }
            std::cout << '\n';
        }
        pe.close();
        return 0;
    } else {
        std::cout << "Unknown command\n";
        pe.close();
        return 0;
    }
}