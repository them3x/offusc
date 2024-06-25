# PyCrypter
Um ofuscador de executavel escrito em Python3

<hr>

#### instalar dependencias:

```
pip3 install cryptography pyinstaller psutil
```

#### Forma de usar

```
python3 main.py <arquivo.exe> <novo_arquivo.py>
```
A saida resultara em um novo arquivo.py junto a um arquivo executavel já empacotado

<hr>

### EXEMPLO PRATICO

Ao criar um keylogger simples em python, que seria facilmente detectado por 100% dos antivirus modernos

![img1](https://raw.githubusercontent.com/them3x/offusc/main/img/key.png)

Ao compilar o codigo a cima, e passa-lo pelo PyCrypter, um novo script python é gerado e compilado com pyinstaller
```
python3 main.py keylogger.exe teste.py
pyinstaller --onefile --clean teste.py
```

O novo executavel gerado, ao ser submetido no [virustotal](https://www.virustotal.com/gui/file/2a3873a2b028a921e84a3de9ae7a00f069d2cdc702fb852fdbdc66686461a636?nocache=1), tem uma eficiencia de ofuscação de 95%

![img1](https://raw.githubusercontent.com/them3x/offusc/main/img/virustotal-cortado.jpeg)


<hr>

#### (OBS: Sim o codigo esta uma bagunça.. no futuro eu organizo kkk)
