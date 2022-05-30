#include "ipk-sniffer.h"

int main(int argc, char **argv)
{
    int opt;
    int option_index = 0;
    int port = -1;
    int pakets = 1;
    char *interface = "";
    bool tcp = false;
    bool udp = false;
    bool both = false;

    static struct option long_options[] = {
        {"tcp", no_argument, 0, 't'},
        {"udp", no_argument, 0, 'u'}};

    // spracovanie argumentov
    while ((opt = getopt_long(argc, argv, "n:i:uthp:", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'h':
            printf("Volanie programu:\n");
            printf("./ipk-sniffer -i rozhraní [-p ­­port] [--tcp|-t] [--udp|-u] [-n num]\n");
            exit(0);
        case 'i':
            interface = optarg;
            break;
        case 'p':
            if (atoi(optarg) < 0 || atoi(optarg) > 65535 || !isdigit(*optarg))
            {
                fprintf(stderr, "Zle zadany port\n");
                exit(1);
            }
            port = atoi(optarg);
            break;
        case 'u':
            udp = true;
            break;
        case 't':
            tcp = true;
            break;
        case 'n':
            if (atoi(optarg) == 0)
            {
                if (!isdigit(*optarg))
                {
                    fprintf(stderr, "Zle zadany pocet paketov\n");
                    exit(1);
                }
                exit(0);
            }
            pakets = atoi(optarg);
            break;
        default:
            return (32);
        }
    }

    // kontrola udp vs tcp nastaveni

    if ((!udp && !tcp) || (udp && tcp))
    {
        both = true;
        udp = false;
        tcp = false;
    }

    pcap_t *processor;

    if (interface == "")
    {
        pcap_if_t *available_devs, *devs;
        char err[100];
        int i = 0;
        pcap_findalldevs(&available_devs, err);
        char *dev, errbuf[PCAP_ERRBUF_SIZE];
        for (available_devs; available_devs; available_devs = available_devs->next)
        {
            printf("%d - %s\n", ++i, available_devs->name);
        }
        exit(0);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // otvorenie live procesora na zachytavanie paketov
    processor = pcap_open_live(interface, 65536, 1, 1000, errbuf);
    if (processor == NULL)
    {
        fprintf(stderr, "Zadany interface sa nepodarilo otvorit\n");
        exit(1);
    }

    // spracovanie a nastaveni filtra na filtrovanie paketov
    struct bpf_program filter_bpf;
    bpf_u_int32 net;

    char filter[32] = "";
    char port_str[10] = "";

    if (tcp)
    {
        strcat(filter, "tcp");
    }
    else if (udp)
    {
        strcat(filter, "udp");
    }
    else if (both)
    {
        strcat(filter, "tcp or udp");
    }

    if (port != -1)
    {
        sprintf(port_str, "%d", port);
        strcat(filter, " and port ");
        strcat(filter, port_str);
    }

    // zistenie typu headeru
    if (pcap_datalink(processor) == 1)
    {
        pkt_type = "eth";
    }
    else
    {
        pkt_type = "ssl";
    }
    // nastavenie filtra na dany procesor
    pcap_compile(processor, &filter_bpf, filter, 0, net);
    if (pcap_setfilter(processor, &filter_bpf) == -1)
    {
        fprintf(stderr, "Chyba pri instalacii filtru");
        exit(1);
    }
    // konecne spustenie loopu na zachytenie paketov
    pcap_loop(processor, pakets, processing, NULL);
    return 0;
}

/*
 * Funkcia processing je loop vsetkych paketov ktore pridu na sniffer a spadaju pod filter urceny vo funkcii main
 * podla typu verzie a typu paketu vola funkcie na spracovanie jednotlivych paketov
 * 
 */

void processing(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    int pkt_header = 0;
    if (pkt_type == "eth")
    {
        pkt_header = sizeof(struct ethhdr);
    }
    else
    {
        pkt_header = sizeof(struct sll_header);
    }
    struct iphdr *iph = (struct iphdr *)(buffer + pkt_header);

    unsigned short iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + pkt_header);
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + pkt_header);
    int header_size;
    struct tm *timebuff = localtime((const time_t *)&header->ts.tv_sec);
    char timebuff_st[24];
    counter = 0;
    // podla verzie rozhodni ktore fcie volat
    if (iph->version == 4)
    {
        // podla switchu rozhodni o ktory protokol sa jedna
        switch (iph->protocol)
        {
        case 6:
            //########################## TCP PAKET ##########################
            header_size = pkt_header + iphdrlen + tcph->doff * 4;
            // najskor vypisem cas a zdrojove adresy a porty
            strftime(timebuff_st, 24, "%H:%M:%S", timebuff);
            printf("%s.%ld", timebuff_st, header->ts.tv_usec);
            process_header(buffer, "TCP");
            // vypisanie hlavicky
            process_data(buffer, header_size, "HEAD");
            printf("\n");
            // vypis dat
            process_data(buffer + header_size, size - header_size, "DATA");
            printf("\n");
            break;
        case 17:
            // ################## UDP PAKET ##################
            header_size = pkt_header + iphdrlen + sizeof(udph);
            strftime(timebuff_st, 24, "%H:%M:%S", timebuff);
            printf("%s.%ld", timebuff_st, header->ts.tv_usec);
            process_header(buffer, "UDP");
            // vypisanie hlavicky
            process_data(buffer, header_size, "HEAD");
            printf("\n");
            // vypis dat
            process_data(buffer + header_size, size - header_size, "DATA");
            printf("\n");
            break;
        default:
            break;
        }
    }
    else
    {
        struct ipv6hdr *iphv6 = (struct ipv6hdr *)(buffer + pkt_header);
        tcph = (struct tcphdr *)(buffer + 40 + pkt_header);
        udph = (struct udphdr *)(buffer + 40 + pkt_header);
        switch (iphv6->nexthdr)
        {
        case 6:
            // ################## TCP PAKET ##################
            header_size = pkt_header + 40 + tcph->doff * 4;
            strftime(timebuff_st, 24, "%H:%M:%S", timebuff);
            printf("%s.%ld", timebuff_st, header->ts.tv_usec);
            process_headerv6(buffer, "TCP");
            process_data(buffer, header_size, "HEAD");
            printf("\n");
            process_data(buffer + header_size, size - header_size, "DATA");
            printf("\n");
            break;
        case 17:
            // ################## UDP PAKET ##################
            header_size = pkt_header + 40 + sizeof(udph);
            strftime(timebuff_st, 24, "%H:%M:%S", timebuff);
            printf("%s.%ld", timebuff_st, header->ts.tv_usec);
            process_headerv6(buffer, "UDP");
            process_data(buffer, header_size, "HEAD");
            printf("\n");
            process_data(buffer + header_size, size - header_size, "DATA");
            printf("\n");
            break;
        default:
            break;
        }
    }
}

/*
 * Funkcia process_header spracuje ipv6 header a vypise udaje o zdrojovom porte a adrese
 * a zaroven o cielovom porte a cielovej adrese
 * 
 */
void process_headerv6(const u_char *buffer, char *type)
{
    char hostbuffer_s[256];
    char hostbuffer_d[256];
    int pkt_header = 0;
    // eth header alebo linuxacky header, podla toho urcim pkt_header velkost
    if (pkt_type == "eth")
    {
        pkt_header = sizeof(struct ethhdr);
    }
    else
    {
        pkt_header = sizeof(struct sll_header);
    }
    // ipv6 ma konstantnu velkost headeru 40 bytov
    struct ipv6hdr *iphv6 = (struct ipv6hdr *)(buffer + pkt_header);
    struct tcphdr *tcph = (struct tcphdr *)(buffer + 40 + pkt_header);
    struct udphdr *udph = (struct udphdr *)(buffer + 40 + pkt_header);

    memset(&sourcev6, 0, sizeof(sourcev6));
    sourcev6.sin6_addr = iphv6->saddr;
    memset(&destv6, 0, sizeof(destv6));
    destv6.sin6_addr = iphv6->daddr;
    destv6.sin6_family = AF_INET6;
    sourcev6.sin6_family = AF_INET6;
    char source_v6[INET6_ADDRSTRLEN];
    char dest_v6[INET6_ADDRSTRLEN];
    // zdrojova ipv6 adresa
    printf(" %s", inet_ntop(AF_INET6, &(sourcev6.sin6_addr), source_v6, sizeof(source_v6)));
    // zdrojovy port
    if (type == "TCP")
    {
        printf(": %d", ntohs(tcph->source));
    }
    else
    {
        printf(": %d", ntohs(udph->source));
    }
    printf(" > ");
    // cielova ipv6 adresa
    printf("%s", inet_ntop(AF_INET6, &(destv6.sin6_addr), dest_v6, sizeof(dest_v6)));
    // cielovy port
    if (type == "TCP")
    {
        printf(" : %d", ntohs(tcph->dest));
    }
    else
    {
        printf(" : %d", ntohs(udph->dest));
    }

    printf("\n\n");
}

/*
 * Funkcia process_header spracuje ipv4 header a vypise udaje o zdrojovom porte a adrese
 * a zaroven o cielovom porte a cielovej adrese
 * 
 */
void process_header(const u_char *buffer, char *type)
{
    unsigned short iphdrlen;
    char hostbuffer_s[256];
    char hostbuffer_d[256];
    int pkt_header = 0;
    // urcenie ci mam normalny eth header alebo linuxacky 
    if (pkt_type == "eth")
    {
        pkt_header = sizeof(struct ethhdr);
    }
    else
    {
        pkt_header = sizeof(struct sll_header);
    }
    struct iphdr *iph = (struct iphdr *)(buffer + pkt_header);
    iphdrlen = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + iphdrlen + pkt_header);
    struct udphdr *udph = (struct udphdr *)(buffer + iphdrlen + pkt_header);

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    dest.sin_family = AF_INET;
    source.sin_family = AF_INET;
    // vypisanie zdrojovej ip
    printf(" %s ", inet_ntoa(source.sin_addr));
    // vypisanie zdrojoveho portu podla tcp udp
    if (type == "TCP")
    {
        printf(": %d", ntohs(tcph->source));
    }
    else
    {
        printf(": %d", ntohs(udph->source));
    }

    printf(" > ");
    //cielova ip
    printf("%s", inet_ntoa(dest.sin_addr));
    // cielovy port
    if (type == "TCP")
    {
        printf(" : %d", ntohs(tcph->dest));
    }
    else
    {
        printf(" : %d", ntohs(udph->dest));
    }
    printf("\n\n");
}

/*
 * Funkcia process_data spracuje data paketu ulozene v premennej data, o velkosti size. 
 * Premenna type sluzi na urcenie ci sa aktualne vypisuje header alebo data, tym mozem
 * na vypise tieto dve polozky oddelit pre lepsiu prehladnost
 */
void process_data(const u_char *data, int size, char *type)
{
    int i, j, k;
    // Ak vypisujem header, ulozim si jeho velkost a budem ju pripisovat ku counteru vo 
    // vypisovani dat
    if (type == "HEAD")
    {
        counter = size;
    }
    // Vypisovanie jednotlivych dat
    for (i = 0; i < size; i++)
    {
        // po vypisani 16 bytov hexa vypisem 16 bytov aj v asci hodnote
        if (i != 0 && i % 16 == 0)
        {
            for (j = i - 16; j < i; j++)
            {
                if (j % 8 == 0)
                {
                    printf(" ");
                }
                // ak je byt asci hodnota tak ho vypisem
                if (data[j] > 32 && data[j] < 127){
                    printf("%c", (unsigned char)data[j]);
                } // ak nie pisem bodku
                else
                    printf(".");
            }
            printf("\n");
        }
        if (i % 16 == 0)
        {
            // paket counter
            if (type == "HEAD")
            {
                printf("0x%04x:", i);
            }
            else
            {
                printf("0x%04x:", i + counter);
            }
        }
        if (i % 8 == 0)
        {
            printf(" ");
        }
        // vypisujem hexadecimalne hodnoty
        printf("%02x ", (unsigned int)data[i]);
        // ak sa riadok nevyplnil cely, dopisem prazdne medzery na zarovnanie
        // a vypisem asci hodnoty znakov ktore sa vypisali
        if (i != 0 && i == size - 1)
        {
            for (k = i + 1; k % 16 != 0; k++)
            {
                printf("   ");
                if (k % 8 == 0)
                {
                    printf(" ");
                }
            }
            for (j = i - ((size - 1) % 16); j <= i; j++)
            {
                if (j % 8 == 0)
                {
                    printf(" ");
                }
                if (data[j] > 32 && data[j] < 127){
                    printf("%c", (unsigned char)data[j]);
                }
                else
                    printf(".");
            }
            printf("\n");
        }
    }
}