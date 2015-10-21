#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#define MAX_PRINT 80
#define MAX_LINE 16

void dispatcherHandler(u_char *,const struct pcap_pkthdr *, const u_char *);
void usage();


int main(int argc, char **argv)
{
    // устанавливаем переменные
    // дескриптор адаптера
    pcap_t *pd;
    // буфер для ошибок
    char error[PCAP_ERRBUF_SIZE];

    // устройство
    char *device=NULL;

    // входной файл
    char *inputFilename = NULL;

    // выходной файл
    char *outFilename = NULL;

    // фильтр
    char *filter = NULL;

    int i = 0;

    // дескриптор выходного файла
    pcap_dumper_t *dumpfile;

    // структура данных
    struct bpf_program fcode;

    // подсеть и маска; тип - для переносимости
    bpf_u_int32 subNet, netMask;

    // если не заданы параметры командной строки - выходим
    if (argc == 1)
    {
        usage();
        return 1;
    }

    // обработка аргументов командной строки
    for(i = 1; i < argc; i += 2)
    {
        switch (argv[i] [1])
        {
        case 'i':
        {
            device=argv[i+1];
        };
        break;

        case 'f':
        {
            inputFilename=argv[i+1];
        };
        break;

        case 'o':
        {
            outFilename=argv[i+1];
        };
        break;

        case 'p':
        {
            filter=argv[i+1];
        };
        break;
        }
    }

    // захват пакетов начинается тут
    if (device != NULL)
    {
        if ( (pd= pcap_open_live(device, BUFSIZ, 1, 0, error) ) == NULL)
        {
            fprintf(stderr,"\nНевозможно открыть устройство\n");
            return 1;
        }
    }
    // обрабатываем файл
    else if (inputFilename != NULL)
    {
        if ( (pd = pcap_open_offline(inputFilename, NULL) ) == NULL)
        {
            fprintf(stderr,"\nНевозможно открыть входной файл\n");
            return 1;
        }
    }
    else usage();

    if (filter != NULL)
    {
        // получаем адрес подсети
        if (device != NULL)
        {
            if(pcap_lookupnet(device, &subNet, &netMask, error)<0)
            {
                fprintf(stderr,"\nНевозможно определить маску подсети.\n");
                return 1;
            }
        }
        else netMask=0xffffff; // в случае работы с файлами - подразумевается что сетевая маска относится к подсетям класса С

        // компилим фильтр
        if(pcap_compile(pd, &fcode, filter, 1, netMask)<0)
        {
              fprintf(stderr,"\nОшибка компиляции фильтра.\n");
              return 1;
        }

        // применяем скомпиленный фильтр
        if(pcap_setfilter(pd, &fcode)<0)
        {
              fprintf(stderr,"\nОшибка установки фильтра\n");
              return 1;
        }
    }

    // открываем файл с дампами пакетов
    if (outFilename != NULL)
    {
        dumpfile = pcap_dump_open(pd, outFilename);

        if (dumpfile == NULL)
        {
              fprintf(stderr,"\nНевозможно открыть выходной файл\n");
              return 1;
        }
    }
    else usage();


    // старт работы
    pcap_loop(pd, 0, dispatcherHandler, (unsigned char *)dumpfile);
}


// хэндлер вызывающий дамп пакетов для каждого входящего пакета
void dispatcherHandler(u_char *dumpfile, const struct pcap_pkthdr *header,
    const u_char *pkt_data)
{
      u_int i = 0;

      // записываем пакет в файл
      pcap_dump(dumpfile,header,pkt_data);

      // принудительно записываем принятый пакет в фдамп
      // гарантированно запишем все пакеты, но с меньшей производительностью
      fflush((FILE*)dumpfile);
}

void usage()
{
    printf("\nВызов:\npf [-i интерфейс(устройство)] | [-f имя входного файла] -o имя выходного файла -p фильтр \n\n");
    return;
}
