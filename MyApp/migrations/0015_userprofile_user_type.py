# Generated by Django 3.2.10 on 2023-05-30 09:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('MyApp', '0014_auto_20230529_1516'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='user_type',
            field=models.CharField(choices=[('hash_editor', 'Hash Editor'), ('has_user', 'Has User')], default='has_user', max_length=50),
        ),
    ]
