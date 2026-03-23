#include <QApplication>
#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QProcess>
#include <QHeaderView>
#include <QMessageBox>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
class FirewallAppBlocker : public QMainWindow {
    Q_OBJECT
public:
    FirewallAppBlocker(QWidget *parent = nullptr) : QMainWindow(parent) {
        table = new QTableWidget(this);
        table->setColumnCount(2);
        table->setHorizontalHeaderLabels({tr("进程名"), tr("路径")});
        table->horizontalHeader()->setStretchLastSection(true);

        QPushButton *refreshBtn = new QPushButton(tr("刷新进程列表"));
        QPushButton *blockBtn   = new QPushButton(tr("阻止网络访问"));
        QPushButton *allowBtn   = new QPushButton(tr("允许网络访问"));

        QHBoxLayout *btnLayout = new QHBoxLayout;
        btnLayout->addWidget(refreshBtn);
        btnLayout->addWidget(blockBtn);
        btnLayout->addWidget(allowBtn);

        QVBoxLayout *mainLayout = new QVBoxLayout;
        mainLayout->addWidget(table);
        mainLayout->addLayout(btnLayout);

        QWidget *central = new QWidget(this);
        central->setLayout(mainLayout);
        setCentralWidget(central);

        setWindowTitle(tr("Firewall App Blocker v1.9"));
        resize(700, 400);

        connect(refreshBtn, &QPushButton::clicked, this, &FirewallAppBlocker::loadProcesses);
        connect(blockBtn,   &QPushButton::clicked, this, &FirewallAppBlocker::blockSelected);
        connect(allowBtn,   &QPushButton::clicked, this, &FirewallAppBlocker::allowSelected);

        loadProcesses();
    }

private slots:
    void loadProcesses() {
        table->setRowCount(0);

        HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap == INVALID_HANDLE_VALUE) return;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hProcessSnap, &pe32)) {
            do {
                int row = table->rowCount();
                table->insertRow(row);
//                table->setItem(row, 0, new QTableWidgetItem(QString::fromWCharArray(pe32.szExeFile)));
                table->setItem(row, 0, new QTableWidgetItem(pe32.szExeFile));

                // 获取进程路径
                QString path = getProcessPath(pe32.th32ProcessID);
                table->setItem(row, 1, new QTableWidgetItem(path));
            } while (Process32Next(hProcessSnap, &pe32));
        }
        CloseHandle(hProcessSnap);
    }

    void blockSelected() {
        int row = table->currentRow();
        if (row < 0) return;

        QString exePath = table->item(row, 1)->text();
        if (exePath.isEmpty()) return;

        QString cmd = QString("netsh advfirewall firewall add rule name=\"Block_%1\" dir=out action=block program=\"%2\" enable=yes")
                          .arg(table->item(row, 0)->text())
                          .arg(exePath);

        if (QProcess::execute(cmd) == 0) {
            QMessageBox::information(this, tr("成功"), tr("已阻止该程序访问网络"));
        } else {
            QMessageBox::warning(this, tr("失败"), tr("防火墙规则添加失败"));
        }
    }

    void allowSelected() {
        int row = table->currentRow();
        if (row < 0) return;

        QString exePath = table->item(row, 1)->text();
        if (exePath.isEmpty()) return;

        QString cmd = QString("netsh advfirewall firewall delete rule name=\"Block_%1\" program=\"%2\"")
                          .arg(table->item(row, 0)->text())
                          .arg(exePath);

        if (QProcess::execute(cmd) == 0) {
            QMessageBox::information(this, tr("成功"), tr("已允许该程序访问网络"));
        } else {
            QMessageBox::warning(this, tr("失败"), tr("防火墙规则删除失败"));
        }
    }

private:
    QTableWidget *table;

    QString getProcessPath(DWORD pid) {
        QString path;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            wchar_t exePath[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, nullptr, exePath, MAX_PATH)) {
                path = QString::fromWCharArray(exePath);
            }
            CloseHandle(hProcess);
        }
        return path;
    }
};

int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setWindowIcon(QIcon(":/icons/icon.png"));
    FirewallAppBlocker window;
    window.show();
    return app.exec();
}
#include "main.moc"
