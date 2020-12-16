# Generated by Django 3.1.3 on 2020-12-14 10:50

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('hub', '0005_token'),
    ]

    operations = [
        migrations.CreateModel(
            name='User',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=40, unique=True)),
                ('password', models.CharField(max_length=200)),
                ('is_admin', models.BooleanField(default=False)),
                ('joined_date', models.DateTimeField(auto_now_add=True)),
                ('modified_at', models.DateTimeField(auto_now=True)),
            ],
            options={
                'db_table': 'users',
            },
        ),
    ]
