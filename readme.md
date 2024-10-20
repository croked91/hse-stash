# Решение задач filestat

## Почему C и GoLang?
Т.к. C/C++ не являются основными языками в работе, для проверки работоспособности алгоритма сначала решаю задачу на golang, а после, при помощи яндекса и спецификации переношу реализацию на C. Можно, конечно, оставить только C и не рассказывать про Go, но чего добру пропадать. Надеюсь, что такое засчитывается.

## Описание задачи
stash. Напишите программу, скрывающую тип файла с целью обеспечить невозможность его чтения стандартными средствами.
Программа должна иметь 2 режима работы - искажение и восстановление.
Режим работы и имя файла передайте с помощью аргументов командной строки.
Максимальный балл - 10.